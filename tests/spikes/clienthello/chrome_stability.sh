#!/usr/bin/env bash
# Is the reference's chrome hello stable across handshakes? Three handshakes,
# three captures, to see whether `HelloChrome_Auto` picks a version per process
# or per connection. usage: chrome_stability.sh <outdir>
set -uo pipefail
OUT="${1:?usage: chrome_stability.sh <outdir>}"
REF="${SING_BOX_REF:-sing-box-ref}"
PORT="${PORT:-9443}"
SOCKS_PORT="${SOCKS_PORT:-21080}"
WORK="$(mktemp -d)"
mkdir -p "$OUT"
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/sink.go" <<'GO'
package main

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func main() {
	outDir := os.Args[1]
	port := os.Args[2]
	ln, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	seen := 0
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn, index int) {
			defer conn.Close()
			conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			buf := make([]byte, 65536)
			n := 0
			for {
				m, err := conn.Read(buf[n:])
				n += m
				if n >= 5 && (int(buf[3])<<8|int(buf[4]))+5 <= n {
					break
				}
				if err != nil || n >= len(buf) {
					break
				}
			}
			if n == 0 {
				return
			}
			out := filepath.Join(outDir, "chrome-"+strconv.Itoa(index)+".bin")
			os.WriteFile(out, buf[:n], 0o644)
		}(conn, seen)
		seen++
	}
}
GO
(cd "$WORK" && go build -o sink ./sink.go) || exit 1

cat > "$WORK/client.json" <<JSON
{
  "log": {"level": "error"},
  "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": $SOCKS_PORT}],
  "outbounds": [{
    "type": "vless", "tag": "out",
    "server": "127.0.0.1", "server_port": $PORT,
    "uuid": "00000000-0000-0000-0000-000000000001",
    "tls": {"enabled": true, "server_name": "www.gstatic.com",
            "utls": {"enabled": true, "fingerprint": "chrome"}}
  }],
  "route": {"rules": [], "final": "out"}
}
JSON

CAPTURE_NAME=x "$WORK/sink" "$OUT" "$PORT" >/dev/null 2>&1 &
SINK=$!
sleep 1
"$REF" run -c "$WORK/client.json" >/dev/null 2>&1 &
REF_PID=$!
sleep 2
for _ in 1 2 3; do
  curl --socks5-hostname "127.0.0.1:$SOCKS_PORT" https://www.gstatic.com/ \
       -o /dev/null -s -m 5 --connect-timeout 3 >/dev/null 2>&1 || true
  sleep 1
done
kill "$REF_PID" "$SINK" 2>/dev/null || true
wait "$REF_PID" 2>/dev/null || true
wait "$SINK" 2>/dev/null || true
md5sum "$OUT"/chrome-*.bin
