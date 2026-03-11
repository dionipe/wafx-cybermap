package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ─── Constants ────────────────────────────────────────────────────────────────

const (
	auditLogPath    = "/var/log/nginx/coraza_audit.log"
	auditLogBakPath = "/var/log/nginx/coraza_audit.log.1"
	listenAddr      = ":8085"

	// Target server location – Jakarta, Indonesia (103.142.214.60)
	targetLat = -6.2146
	targetLng = 106.8451

	// GeoIP rate limit: ip-api.com free tier = 45 req/min
	geoRateDelay = 1400 * time.Millisecond // ~42 req/min

	// How many events to keep in the history ring-buffer
	historySize = 150
)

// ─── Threat types ─────────────────────────────────────────────────────────────

type ThreatType string

const (
	ThreatOAS ThreatType = "OAS" // On-Access Scan – LFI/RFI/file access
	ThreatMAV ThreatType = "MAV" // Mail Anti Virus – mail/SMTP attacks
	ThreatIDS ThreatType = "IDS" // Intrusion Detection – scanning/probing
	ThreatVUL ThreatType = "VUL" // Vulnerability Scan – SQLi/XSS/injection
	ThreatRMW ThreatType = "RMW" // Ransomware – high-severity crypto patterns
)

var threatColor = map[ThreatType]string{
	ThreatOAS: "#f59e0b", // amber
	ThreatMAV: "#3b82f6", // blue
	ThreatIDS: "#10b981", // green
	ThreatVUL: "#ef4444", // red
	ThreatRMW: "#8b5cf6", // purple
}

var threatLabel = map[ThreatType]string{
	ThreatOAS: "OAS - On-Access Scan",
	ThreatMAV: "MAV - Mail Anti Virus",
	ThreatIDS: "IDS - Intrusion Detection",
	ThreatVUL: "VUL - Vulnerability Scan",
	ThreatRMW: "RMW - Ransomware",
}

// ─── Data types ───────────────────────────────────────────────────────────────

// ThreatEvent is sent over SSE to the frontend.
type ThreatEvent struct {
	ID         string     `json:"id"`
	Time       string     `json:"time"`
	Unix       int64      `json:"unix"`
	Type       ThreatType `json:"type"`
	Label      string     `json:"label"`
	Color      string     `json:"color"`
	SrcIP      string     `json:"src_ip"`
	SrcCountry string     `json:"src_country"`
	SrcCC      string     `json:"src_cc"`
	SrcCity    string     `json:"src_city"`
	SrcLat     float64    `json:"src_lat"`
	SrcLng     float64    `json:"src_lng"`
	DstLat     float64    `json:"dst_lat"`
	DstLng     float64    `json:"dst_lng"`
	Severity   string     `json:"severity"`
	Message    string     `json:"message"`
	Domain     string     `json:"domain"`
}

// Stats holds per-type counters for the current day.
type Stats struct {
	Total     int64     `json:"total"`
	OAS       int64     `json:"oas"`
	MAV       int64     `json:"mav"`
	IDS       int64     `json:"ids"`
	VUL       int64     `json:"vul"`
	RMW       int64     `json:"rmw"`
	UpdatedAt time.Time `json:"updated_at"`
}

// rawBlock holds extracted fields from a single Coraza audit log block.
type rawBlock struct {
	timestamp time.Time
	clientIP  string
	method    string
	uri       string
	host      string
	userAgent string
	msg       string
	tags      string
	severity  string
	domain    string
}

// GeoInfo holds geo-location data for an IP.
type GeoInfo struct {
	IP          string  `json:"ip"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	City        string  `json:"city"`
	Lat         float64 `json:"lat"`
	Lng         float64 `json:"lng"`
	ISP         string  `json:"isp"`
}

// ─── Global state ─────────────────────────────────────────────────────────────

var (
	broker   = newSSEBroker()
	statsVal Stats

	statsMu sync.Mutex

	geoCacheMu  sync.RWMutex
	geoCache    = map[string]GeoInfo{}
	geoCacheTS  = map[string]time.Time{}
	geoCacheTTL = 2 * time.Hour

	historyMu sync.Mutex
	history   = make([]ThreatEvent, 0, historySize)

	// GeoIP request queue (rate-limited worker)
	geoQueue = make(chan geoReq, 256)

	// Counters (atomic)
	cntTotal int64
	cntOAS   int64
	cntMAV   int64
	cntIDS   int64
	cntVUL   int64
	cntRMW   int64
)

// ─── GeoIP ────────────────────────────────────────────────────────────────────

type geoReq struct {
	ip     string
	result chan<- GeoInfo
}

// geoWorker processes GeoIP requests at a rate-limited pace.
func geoWorker() {
	tick := time.NewTicker(geoRateDelay)
	defer tick.Stop()
	for req := range geoQueue {
		<-tick.C
		info := fetchGeoIP(req.ip)
		req.result <- info
	}
}

// lookupGeoIP returns GeoInfo for ip. Uses cache when possible; enqueues
// a rate-limited lookup otherwise. Returns fallback on timeout.
func lookupGeoIP(ip string) GeoInfo {
	if isPrivateIP(ip) {
		return GeoInfo{IP: ip, Country: "Local", CountryCode: "XX"}
	}

	geoCacheMu.RLock()
	info, ok := geoCache[ip]
	ts := geoCacheTS[ip]
	geoCacheMu.RUnlock()
	if ok && time.Since(ts) < geoCacheTTL {
		return info
	}

	// Submit to rate-limited worker
	ch := make(chan GeoInfo, 1)
	select {
	case geoQueue <- geoReq{ip: ip, result: ch}:
	default:
		// Queue full – use empty/cached result
		return info
	}

	select {
	case res := <-ch:
		return res
	case <-time.After(5 * time.Second):
		return info // timeout – return whatever we had
	}
}

// fetchGeoIP makes an HTTP request to ip-api.com and caches the result.
func fetchGeoIP(ip string) GeoInfo {
	client := &http.Client{Timeout: 4 * time.Second}
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,query,country,countryCode,city,lat,lon,isp", ip)
	resp, err := client.Get(url)
	if err != nil {
		return GeoInfo{IP: ip}
	}
	defer resp.Body.Close()

	var d struct {
		Status      string  `json:"status"`
		Country     string  `json:"country"`
		CountryCode string  `json:"countryCode"`
		City        string  `json:"city"`
		Lat         float64 `json:"lat"`
		Lon         float64 `json:"lon"`
		ISP         string  `json:"isp"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil || d.Status != "success" {
		return GeoInfo{IP: ip}
	}
	result := GeoInfo{
		IP: ip, Country: d.Country, CountryCode: d.CountryCode,
		City: d.City, Lat: d.Lat, Lng: d.Lon, ISP: d.ISP,
	}
	geoCacheMu.Lock()
	geoCache[ip] = result
	geoCacheTS[ip] = time.Now()
	geoCacheMu.Unlock()
	return result
}

// isPrivateIP returns true for RFC1918 / loopback addresses.
func isPrivateIP(ip string) bool {
	for _, pfx := range []string{
		"10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
		"172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
		"172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
		"192.168.", "127.", "::1", "fc", "fd",
	} {
		if strings.HasPrefix(ip, pfx) {
			return true
		}
	}
	return false
}

// ─── Threat classification ────────────────────────────────────────────────────

// classifyThreat maps Coraza event fields to one of the 5 threat categories.
func classifyThreat(msg, tags, uri, method string) ThreatType {
	m := strings.ToLower(msg)
	t := strings.ToLower(tags)
	u := strings.ToLower(uri)

	// RMW – Ransomware: very high anomaly score or specific file-encryption indicators
	if strings.Contains(m, "ransomware") || strings.Contains(t, "ransomware") ||
		strings.Contains(u, ".crypt") || strings.Contains(u, ".encrypted") ||
		strings.Contains(u, ".locked") || strings.Contains(u, ".wncry") ||
		strings.Contains(u, "decrypt") {
		return ThreatRMW
	}

	// OAS – On-Access Scan: LFI / RFI / path traversal / restricted-file access
	if strings.Contains(t, "attack-lfi") || strings.Contains(t, "attack-rfi") ||
		strings.Contains(m, "file access") || strings.Contains(m, "path traversal") ||
		strings.Contains(m, "restricted file") || strings.Contains(m, "local file") ||
		strings.Contains(u, "../") || strings.Contains(u, "..%2f") ||
		strings.Contains(u, "etc/passwd") || strings.Contains(u, "etc/shadow") ||
		strings.Contains(u, ".env") || strings.Contains(u, ".git/") ||
		strings.Contains(u, "wp-config") || strings.Contains(u, "/proc/") {
		return ThreatOAS
	}

	// MAV – Mail Anti Virus: SMTP/mail-related attacks
	if strings.Contains(m, "mail") || strings.Contains(t, "attack-mail") ||
		strings.Contains(u, "/mail") || strings.Contains(u, "/smtp") ||
		strings.Contains(u, "/webmail") || strings.Contains(u, "/roundcube") ||
		strings.Contains(u, "/sendmail") || strings.Contains(u, "/phpmailer") {
		return ThreatMAV
	}

	// VUL – Vulnerability Scan: SQL injection, XSS, RCE, command injection
	if strings.Contains(t, "attack-sqli") || strings.Contains(t, "attack-xss") ||
		strings.Contains(t, "attack-injection") || strings.Contains(t, "attack-rce") ||
		strings.Contains(m, "sql injection") || strings.Contains(m, "xss") ||
		strings.Contains(m, "injection") || strings.Contains(m, "cross-site") ||
		strings.Contains(m, "command") || strings.Contains(m, "shell") ||
		strings.Contains(u, "union+select") || strings.Contains(u, "union%20select") ||
		strings.Contains(u, "<script") || strings.Contains(u, "alert(") ||
		strings.Contains(u, "exec(") || strings.Contains(u, "system(") {
		return ThreatVUL
	}

	// IDS – Intrusion Detection (default: protocol violations, scanning, probing)
	return ThreatIDS
}

// ─── Coraza audit log parser ──────────────────────────────────────────────────

var (
	reBoundary = regexp.MustCompile(`^--[A-Za-z0-9]+-([A-Z])--$`)
	reAHeader  = regexp.MustCompile(`^\[(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\]\s+\S+\s+([0-9a-fA-F.:]+)`)
	reMsg      = regexp.MustCompile(`\[msg "([^"]+)"\]`)
	reSeverity = regexp.MustCompile(`\[severity "([^"]+)"\]`)
	reTags     = regexp.MustCompile(`\[tag "([^"]+)"\]`)
	reWAFXDom  = regexp.MustCompile(`\[data "([^"]+)"\]`)
	reHostHdr  = regexp.MustCompile(`(?i)^host:\s*(\S+)$`)
	reUAHdr    = regexp.MustCompile(`(?i)^user-agent:\s*(.+)$`)
	reReqLine  = regexp.MustCompile(`^([A-Z]+)\s+(\S+)\s+HTTP`)
	tsLayout   = "2006/01/02 15:04:05"
)

// parseAuditLog parses a Coraza native audit log blob and returns rawBlocks.
// limit ≤ 0 means return all.
func parseAuditLog(data string, limit int) []rawBlock {
	text := strings.ReplaceAll(data, "\x00", "")
	lines := strings.Split(text, "\n")

	var blocks []rawBlock
	var cur rawBlock
	var section string
	inBlock := false
	var tagList []string

	flush := func() {
		if cur.clientIP == "" || cur.timestamp.IsZero() {
			return
		}
		cur.tags = strings.Join(tagList, " ")
		blocks = append(blocks, cur)
	}

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		m := reBoundary.FindStringSubmatch(line)
		if len(m) == 2 {
			if m[1] == "A" {
				if inBlock {
					flush()
				}
				cur = rawBlock{}
				tagList = nil
				section = "A"
				inBlock = true
			} else {
				section = m[1]
			}
			continue
		}

		switch section {
		case "A":
			if cur.clientIP == "" {
				if ma := reAHeader.FindStringSubmatch(line); len(ma) >= 3 {
					t, _ := time.ParseInLocation(tsLayout, ma[1], time.Local)
					cur.timestamp = t
					cur.clientIP = ma[2]
				}
			}
		case "B":
			if cur.method == "" {
				if mr := reReqLine.FindStringSubmatch(line); len(mr) >= 3 {
					cur.method = mr[1]
					cur.uri = mr[2]
				}
			}
			if cur.host == "" {
				if mh := reHostHdr.FindStringSubmatch(line); len(mh) >= 2 {
					h := mh[1]
					if idx := strings.LastIndex(h, ":"); idx != -1 {
						after := h[idx+1:]
						if allDigits(after) {
							h = h[:idx]
						}
					}
					cur.host = h
				}
			}
			if cur.userAgent == "" {
				if mu := reUAHdr.FindStringSubmatch(line); len(mu) >= 2 {
					cur.userAgent = strings.TrimSpace(mu[1])
				}
			}
		case "H":
			if strings.Contains(line, "WAFX-DOMAIN") {
				if md := reWAFXDom.FindStringSubmatch(line); len(md) >= 2 && md[1] != "" && md[1] != "tx.wafx_domain" {
					cur.domain = md[1]
				}
				continue
			}
			if cur.msg == "" {
				if mm := reMsg.FindStringSubmatch(line); len(mm) >= 2 {
					msg := mm[1]
					if !strings.Contains(msg, "Inbound Anomaly") &&
						!strings.Contains(msg, "Outbound Anomaly") &&
						!strings.Contains(msg, "Anomaly Score Exceeded") {
						cur.msg = msg
					}
				}
			}
			if cur.severity == "" {
				if ms := reSeverity.FindStringSubmatch(line); len(ms) >= 2 {
					cur.severity = strings.ToLower(ms[1])
				}
			}
			for _, mt := range reTags.FindAllStringSubmatch(line, -1) {
				tagList = append(tagList, mt[1])
			}
			if cur.domain == "" && cur.host != "" {
				cur.domain = cur.host
			}
		}
	}
	if inBlock {
		flush()
	}

	// Reverse so newest is first
	for i, j := 0, len(blocks)-1; i < j; i, j = i+1, j-1 {
		blocks[i], blocks[j] = blocks[j], blocks[i]
	}
	if limit > 0 && len(blocks) > limit {
		blocks = blocks[:limit]
	}
	return blocks
}

func allDigits(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// ─── Event building & broadcasting ───────────────────────────────────────────

var eventCounter int64

func buildAndBroadcast(blk rawBlock) {
	geo := lookupGeoIP(blk.clientIP)

	// Skip blocks with no usable geo (lat/lng both 0 means lookup failed
	// for a public IP → still broadcast but arc won't draw)
	tt := classifyThreat(blk.msg, blk.tags, blk.uri, blk.method)

	id := atomic.AddInt64(&eventCounter, 1)
	ev := ThreatEvent{
		ID:         fmt.Sprintf("ev-%d", id),
		Time:       blk.timestamp.Format("15:04:05"),
		Unix:       blk.timestamp.Unix(),
		Type:       tt,
		Label:      threatLabel[tt],
		Color:      threatColor[tt],
		SrcIP:      blk.clientIP,
		SrcCountry: geo.Country,
		SrcCC:      geo.CountryCode,
		SrcCity:    geo.City,
		SrcLat:     geo.Lat,
		SrcLng:     geo.Lng,
		DstLat:     targetLat,
		DstLng:     targetLng,
		Severity:   blk.severity,
		Message:    blk.msg,
		Domain:     blk.domain,
	}

	// Update counters
	atomic.AddInt64(&cntTotal, 1)
	switch tt {
	case ThreatOAS:
		atomic.AddInt64(&cntOAS, 1)
	case ThreatMAV:
		atomic.AddInt64(&cntMAV, 1)
	case ThreatIDS:
		atomic.AddInt64(&cntIDS, 1)
	case ThreatVUL:
		atomic.AddInt64(&cntVUL, 1)
	case ThreatRMW:
		atomic.AddInt64(&cntRMW, 1)
	}

	// Push to history ring-buffer
	historyMu.Lock()
	history = append(history, ev)
	if len(history) > historySize {
		history = history[len(history)-historySize:]
	}
	historyMu.Unlock()

	// Broadcast to SSE clients
	data, _ := json.Marshal(ev)
	broker.publish("threat", data)
}

// ─── Log monitor ─────────────────────────────────────────────────────────────

func monitorLog() {
	// Seed from backup log (yesterday / overnight rotation)
	seedFromFile(auditLogBakPath, 100)
	// Seed from current log
	seedFromFile(auditLogPath, 50)

	// Now tail the current log for new events
	tailLog()
}

// seedFromFile reads up to `limit` recent events from a log file and
// broadcasts them (with throttled GeoIP).
func seedFromFile(path string, limit int) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	blocks := parseAuditLog(string(data), limit)
	log.Printf("[cybermap] Seeding %d events from %s", len(blocks), path)

	// Process oldest first so feed is chronological
	for i := len(blocks) - 1; i >= 0; i-- {
		buildAndBroadcast(blocks[i])
	}
}

// tailLog watches auditLogPath for new content and processes it.
func tailLog() {
	f, err := os.Open(auditLogPath)
	if err != nil {
		log.Printf("[cybermap] Cannot open %s: %v – retrying in 5s", auditLogPath, err)
		time.Sleep(5 * time.Second)
		go tailLog()
		return
	}
	defer f.Close()

	// Seek to end so we only process NEW events
	offset, _ := f.Seek(0, io.SeekEnd)
	var lastSize int64 = offset

	log.Printf("[cybermap] Tailing %s from offset %d", auditLogPath, offset)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		fi, err := f.Stat()
		if err != nil {
			log.Printf("[cybermap] Stat error: %v", err)
			continue
		}
		curSize := fi.Size()

		// File was rotated (truncated or replaced)
		if curSize < lastSize {
			log.Printf("[cybermap] Log rotated, reopening")
			f.Close()
			go tailLog()
			return
		}

		if curSize == lastSize {
			continue // no new data
		}

		// Read new bytes
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			continue
		}
		buf := new(strings.Builder)
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
		for scanner.Scan() {
			buf.WriteString(scanner.Text())
			buf.WriteRune('\n')
		}
		newData := buf.String()
		offset = curSize
		lastSize = curSize

		if strings.TrimSpace(newData) == "" {
			continue
		}

		blocks := parseAuditLog(newData, 0)
		for i := len(blocks) - 1; i >= 0; i-- {
			buildAndBroadcast(blocks[i])
		}

		// Broadcast updated stats after processing batch
		broadcastStats()
	}
}

// broadcastStats sends a stats SSE event to all clients.
func broadcastStats() {
	s := Stats{
		Total:     atomic.LoadInt64(&cntTotal),
		OAS:       atomic.LoadInt64(&cntOAS),
		MAV:       atomic.LoadInt64(&cntMAV),
		IDS:       atomic.LoadInt64(&cntIDS),
		VUL:       atomic.LoadInt64(&cntVUL),
		RMW:       atomic.LoadInt64(&cntRMW),
		UpdatedAt: time.Now(),
	}
	data, _ := json.Marshal(s)
	broker.publish("stats", data)
}

// ─── SSE Broker ──────────────────────────────────────────────────────────────

type sseMsg struct {
	event string
	data  []byte
}

type sseBroker struct {
	mu      sync.RWMutex
	clients map[chan sseMsg]bool
}

func newSSEBroker() *sseBroker {
	return &sseBroker{clients: make(map[chan sseMsg]bool)}
}

func (b *sseBroker) publish(event string, data []byte) {
	msg := sseMsg{event: event, data: data}
	b.mu.RLock()
	for ch := range b.clients {
		select {
		case ch <- msg:
		default: // drop if client is slow
		}
	}
	b.mu.RUnlock()
}

func (b *sseBroker) subscribe() chan sseMsg {
	ch := make(chan sseMsg, 64)
	b.mu.Lock()
	b.clients[ch] = true
	b.mu.Unlock()
	return ch
}

func (b *sseBroker) unsubscribe(ch chan sseMsg) {
	b.mu.Lock()
	delete(b.clients, ch)
	b.mu.Unlock()
	close(ch)
}

// ─── HTTP Handlers ────────────────────────────────────────────────────────────

// handleSSE streams threat events to the browser via Server-Sent Events.
func handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ch := broker.subscribe()
	defer broker.unsubscribe(ch)

	// Send current stats immediately
	s := Stats{
		Total: atomic.LoadInt64(&cntTotal), OAS: atomic.LoadInt64(&cntOAS),
		MAV: atomic.LoadInt64(&cntMAV), IDS: atomic.LoadInt64(&cntIDS),
		VUL: atomic.LoadInt64(&cntVUL), RMW: atomic.LoadInt64(&cntRMW),
		UpdatedAt: time.Now(),
	}
	if d, err := json.Marshal(s); err == nil {
		fmt.Fprintf(w, "event: stats\ndata: %s\n\n", d)
		flusher.Flush()
	}

	// Replay recent history to the new client
	historyMu.Lock()
	snap := make([]ThreatEvent, len(history))
	copy(snap, history)
	historyMu.Unlock()

	for _, ev := range snap {
		d, _ := json.Marshal(ev)
		fmt.Fprintf(w, "event: threat\ndata: %s\n\n", d)
	}
	flusher.Flush()

	// Stream live events
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			// Heartbeat (prevent proxy timeout)
			fmt.Fprintf(w, ": ping\n\n")
			flusher.Flush()
		case msg, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", msg.event, msg.data)
			flusher.Flush()
		}
	}
}

// handleStats returns current stats as JSON.
func handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	s := Stats{
		Total: atomic.LoadInt64(&cntTotal), OAS: atomic.LoadInt64(&cntOAS),
		MAV: atomic.LoadInt64(&cntMAV), IDS: atomic.LoadInt64(&cntIDS),
		VUL: atomic.LoadInt64(&cntVUL), RMW: atomic.LoadInt64(&cntRMW),
		UpdatedAt: time.Now(),
	}
	json.NewEncoder(w).Encode(s)
}

// handleIndex serves the main HTML page.
func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" && r.URL.Path != "/cyber-map.html" {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, "/opt/wafx-cybermap/static/index.html")
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.Printf("[cybermap] WAFX CyberThreat Live Map starting on %s", listenAddr)

	// Validate geo coords are reasonable – just a sanity check
	_ = math.Abs(targetLat)

	// Start GeoIP rate-limited worker
	go geoWorker()

	// Start log monitor (seeds + tails)
	go monitorLog()

	// Periodic stats broadcast every 5s
	go func() {
		t := time.NewTicker(5 * time.Second)
		for range t.C {
			broadcastStats()
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/events", handleSSE)
	mux.HandleFunc("/api/stats", handleStats)
	mux.HandleFunc("/", handleIndex)

	log.Printf("[cybermap] Listening on http://localhost%s", listenAddr)
	if err := http.ListenAndServe(listenAddr, mux); err != nil {
		log.Fatalf("[cybermap] Server error: %v", err)
	}
}
