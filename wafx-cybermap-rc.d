#!/bin/sh

# PROVIDE: wafx-cybermap
# REQUIRE: DAEMON NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="wafx_cybermap"
rcvar="wafx_cybermap_enable"

load_rc_config $name

: ${wafx_cybermap_enable:="NO"}
: ${wafx_cybermap_user:="root"}

# 1. Gunakan nama variabel yang berbeda untuk path asli aplikasi
wafxcybermap_file="/opt/wafx-cybermap/wafx-cybermap"

# 2. 'command' haruslah si pembungkus (daemon)
command="/usr/sbin/daemon"

# 3. 'pidfile' harus didefinisikan agar rc.subr bisa mengecek statusnya
pidfile="/var/run/${name}.pid"

# 4. 'command_args' berisi instruksi untuk si 'daemon'
# Tambahkan -f agar daemon tetap mengawasi prosesnya
command_args="-f -P ${pidfile} -o /var/log/wafx-cybermap.log ${wafxcybermap_file}"

# Opsi tambahan jika aplikasi butuh pindah folder dulu
wafxcybermap_chdir="/opt/wafx-cybermap"

run_rc_command "$1"