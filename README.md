# WAFX CyberThreat Live Map

🌐 **Live:** [https://ctmap.indobsd.id](https://ctmap.indobsd.id)  
🛡️ **WAFX Platform:** [https://wafx.indobsd.id](https://wafx.indobsd.id)

Visualisasi serangan siber secara real-time berbasis peta dunia interaktif. Data diambil langsung dari log audit **WAFX-NGINX Coraza WAF** yang sedang berjalan, kemudian ditampilkan sebagai animasi arc balistik dari lokasi penyerang menuju server target.

```
┌─────────────────────────────────────────────────────────┐
│  WAFX CyberThreat Live Map  │  01:47:32   │ 1,240 Total │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  🗺  Peta Dunia (CartoDB Dark Matter)                   │
│      ← arc animasi berwarna per kategori ancaman        │
│      ● Target: Jakarta, Indonesia                       │
│                                                         │
│  [OAS]  240    [MAV]  58     [IDS]  891                 │
│  [VUL]  42     [RMW]   9                                │
│                                                         │
│  ┌─── Global Attack Feed ──────────────────────────┐   │
│  │ IDS  01:47:31  45.12.33.154   Germany           │   │
│  │ VUL  01:47:29  182.2.71.0     China             │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

---

## Peruntukan

| Pengguna | Kegunaan |
|---|---|
| **SOC / Security Analyst** | Memantau serangan masuk secara real-time tanpa membuka log mentah |
| **System Administrator** | Melihat distribusi geografis penyerang dan kategori ancaman dominan |
| **Network Operations Center (NOC)** | Display dinding (wall display) sebagai live threat intelligence feed |
| **Audit & Compliance** | Bukti visual bahwa WAF aktif mendeteksi dan memblokir ancaman |

---

## Kategori Ancaman

| Kode | Nama Lengkap | Warna | Pemicu |
|---|---|---|---|
| **OAS** | On-Access Scan | 🟡 Amber | LFI, RFI, path traversal (`../`), akses file sensitif (`.env`, `.git`, `wp-config`) |
| **MAV** | Mail Anti Virus | 🔵 Biru | Serangan SMTP/webmail, PHPMailer injection, `/mail`, `/roundcube` |
| **IDS** | Intrusion Detection Scan | 🟢 Hijau | Protocol violation, missing Host header, HTTP method probing, scanning umum |
| **VUL** | Vulnerability Scan | 🔴 Merah | SQL injection, XSS, command injection, RCE (`attack-sqli`, `attack-xss`) |
| **RMW** | Ransomware | 🟣 Ungu | Pola ekstensi file terenkripsi (`.crypt`, `.wncry`, `.locked`), akses `/decrypt` |

---

## Arsitektur

```
┌──────────────────────────────────────────────────────────────────┐
│                        SERVER                                    │
│                                                                  │
│  ┌──────────────┐    parse + tail    ┌────────────────────────┐  │
│  │ Coraza Audit │ ─────────────────► │   Go Backend           │  │
│  │ Log          │                    │   wafx-cybermap        │  │
│  │ /var/log/    │                    │   :8085                │  │
│  │ nginx/       │  GeoIP lookup      │                        │  │
│  │ coraza_audit │ ◄── ip-api.com ──► │  SSE /api/events       │  │
│  │ .log         │                    │  JSON /api/stats       │  │
│  └──────────────┘                    └──────────┬─────────────┘  │
│                                                  │               │
│  ┌───────────────────────────────────────────────▼─────────────┐ │
│  │  Nginx Reverse Proxy  :8083  →  localhost:8085              │ │
│  └─────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
                                │  SSE stream
                                ▼
                    ┌───────────────────────┐
                    │  Browser              │
                    │  Leaflet.js Map       │
                    │  Canvas Arc Animation │
                    │  Stats Panel + Feed   │
                    └───────────────────────┘
```

---

## Cara Kerja

### 1. Parsing Log Coraza (Backend Go)

Coraza WAF menulis log audit ke `/var/log/nginx/coraza_audit.log` dalam format native multi-section:

```
--<ID>-A--
[2026/03/12 01:34:08] <txid> <client_ip> <port> <server_ip> <port>
--<ID>-B--
GET /wp-config.php HTTP/1.1
Host: example.com
User-Agent: python-requests/2.28
--<ID>-H--
[msg "Restricted File Access Attempt"][severity "CRITICAL"]
[tag "attack-lfi"][tag "OWASP_CRS"]
```

Backend mem-parse setiap **block A→Z** menggunakan regex:
- **Section A** → timestamp + client IP
- **Section B** → HTTP method, URI, Host header, User-Agent
- **Section H** → msg, severity, tags (digunakan untuk klasifikasi kategori)

### 2. Klasifikasi Ancaman

Setiap block yang berhasil di-parse diklasifikasikan ke salah satu dari 5 kategori berdasarkan **prioritas berurutan**:

```
RMW → OAS → MAV → VUL → IDS (default)
```

Klasifikasi memeriksa kombinasi: `[msg]`, `[tag]`, URI, dan HTTP method.

### 3. GeoIP Lookup

Client IP di-resolve ke koordinat geografis menggunakan **ip-api.com** (free tier):

- Rate-limited: **~42 request/menit** (aman di bawah limit 45/menit)
- Cache per IP selama **2 jam** (in-memory)
- IP privat/loopback langsung dikembalikan sebagai `"Local"` tanpa request

### 4. Server-Sent Events (SSE)

Backend mem-push dua jenis event ke browser:

| Event | Payload | Kapan |
|---|---|---|
| `threat` | JSON satu ThreatEvent (IP, geo, tipe, warna, koordinat) | Setiap event baru |
| `stats` | JSON counter OAS/MAV/IDS/VUL/RMW + total | Setiap 5 detik |

Client baru yang baru connect menerima **replay 150 event terakhir** sebelum live stream dimulai.

### 5. Log Tailing Real-Time

```
startup
  ├── seedFromFile(coraza_audit.log.1, 100)   ← event kemarin
  ├── seedFromFile(coraza_audit.log,   50)    ← event hari ini
  └── tailLog()                               ← poll setiap 2 detik
             │
             ├── detect file rotation (size < last)  → reopen
             └── read new bytes → parse → broadcast
```

### 6. Playback Engine (Frontend)

Saat halaman di-refresh, event history tidak langsung muncul sekaligus melainkan **dianimasikan satu per satu**:

```
Browser connect SSE
       │
       ▼
  [collect]  ──► buffer semua event lama (unix age > 60 detik)
       │         tunggu 450ms keheningan
       ▼
  [play]     ──► animasi 1 event setiap 320ms
       │         arc + feed item + counter naik satu-satu
       ▼
  [live]     ──► event real-time tampil langsung
       │         setelah 2.2 detik sepi...
       ▼
  [loop]     ──► ulang arc dari event pertama (counter terus naik)
       │         feed tidak ditambah (tidak duplikat)
       └──────► kembali ke [live] → [loop] → selamanya ♾
```

### 7. Animasi Arc Canvas

Arc digambar menggunakan **Bézier quadratic** di `<canvas>` overlay Leaflet:

```
Control point (lifted)
       ▲
       │ lift = min(distance × 0.42, 220px)
       │
src ───┼─── (animated) ───► dst (Jakarta)
```

Setiap arc memiliki 3 fase waktu:
- **travel** (2200ms): titik bergerak dari src ke dst
- **hold** (800ms): arc penuh ditampilkan
- **fade** (1200ms): arc memudar menghilang

---

## Struktur File

```
/opt/wafx-cybermap/
├── main.go                  # Go backend (SSE, log parser, GeoIP)
├── go.mod                   # Go module
├── wafx-cybermap            # Binary hasil build
└── static/
    └── index.html           # Frontend (Leaflet map, canvas, SSE client)

/etc/systemd/system/
└── wafx-cybermap.service    # Systemd unit (auto-start)

/etc/nginx/conf.d/
└── wafx-cybermap.conf       # Nginx reverse proxy :8083 → :8085
```

---

## Instalasi & Build

```bash
cd /opt/wafx-cybermap
go build -o wafx-cybermap .
```

### Jalankan via systemd (recommended)

```bash
systemctl start   wafx-cybermap
systemctl stop    wafx-cybermap
systemctl restart wafx-cybermap
systemctl status  wafx-cybermap

# Aktifkan auto-start saat boot
systemctl enable  wafx-cybermap

# Lihat log
journalctl -u wafx-cybermap -f
```

### Jalankan manual (foreground)

```bash
./wafx-cybermap
```

---

## Akses

### Publik

| URL | Keterangan |
|---|---|
| [https://ctmap.indobsd.id](https://ctmap.indobsd.id) | **Live map** (production) |
| [https://wafx.indobsd.id](https://wafx.indobsd.id) | **WAFX Security Platform** |

### Lokal / Internal

| URL | Keterangan |
|---|---|
| `http://localhost:8083/` | Via Nginx reverse proxy (port standar) |
| `http://localhost:8083/cyber-map.html` | Alias path |
| `http://localhost:8085/` | Langsung ke Go service |
| `http://localhost:8085/api/stats` | JSON stats (total, per kategori) |
| `http://localhost:8085/api/events` | SSE stream (text/event-stream) |

---

## Konfigurasi

Konstanta utama di [main.go](main.go):

| Konstanta | Default | Keterangan |
|---|---|---|
| `auditLogPath` | `/var/log/nginx/coraza_audit.log` | Log aktif Coraza |
| `auditLogBakPath` | `/var/log/nginx/coraza_audit.log.1` | Log rotasi (kemarin) |
| `listenAddr` | `:8085` | Port Go service |
| `targetLat` / `targetLng` | `-6.2146` / `106.8451` | Koordinat server target (Jakarta) |
| `geoRateDelay` | `1400ms` | Interval antar GeoIP request |
| `geoCacheTTL` | `2 jam` | Durasi cache GeoIP per IP |
| `historySize` | `150` | Maksimal event di ring-buffer |

---

## Dependensi

| Komponen | Versi | Keterangan |
|---|---|---|
| Go | ≥ 1.21 | Standard library only, tidak ada external package |
| Leaflet.js | 1.9.4 | Peta interaktif (CDN) |
| CartoDB Dark Matter | — | Tile layer peta gelap (free, no key) |
| ip-api.com | free tier | GeoIP lookup (45 req/min, no key) |
| WAFX-NGINX Coraza | — | Sumber data log audit |

---

## Catatan Keamanan

- Service berjalan di port **8085** yang tidak terekspos langsung ke internet — diakses melalui Nginx yang sudah dikonfigurasi dengan WAF rules
- Direktif `coraza off` pada nginx config untuk endpoint `/api/events` mencegah Coraza memblokir SSE stream yang legitimate
- GeoIP hanya dilakukan untuk **public IP** — IP privat (RFC1918) dan loopback tidak dikirim ke api eksternal
- Tidak ada autentikasi pada service ini karena didesain untuk akses internal/LAN saja
