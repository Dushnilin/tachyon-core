#!/usr/bin/env bash
# Capture the ClientHello of every uTLS fingerprint the reference offers.
# The reference is the client here: a socks inbound takes our request, the
# vless outbound dials this sink, and the sink writes the first record.
# usage: capture_fingerprints.sh <outdir>
set -uo pipefail
OUT="${1:?usage: capture_fingerprints.sh <outdir>}"
REF="${SING_BOX_REF:-sing-box-ref}"
PORT="${PORT:-9443}"
SOCKS_PORT="${SOCKS_PORT:-21080}"
WORK="$(mktemp -d)"
BIN="$WORK/sink"
mkdir -p "$OUT"
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/sink.go" <<'GO'
package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

func main() {
	outDir := os.Args[1]
	port := os.Args[2]
	os.MkdirAll(outDir, 0o755)
	ln, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	fmt.Println("listening on", ln.Addr())
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()
			conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			// a ClientHello above ~1.4 KiB spans two segments, so read
			// until the handshake record is whole
			buf := make([]byte, 65536)
			n := 0
			for {
				m, err := conn.Read(buf[n:])
				n += m
				if n >= 5 && int(buf[3])<<8|int(buf[4])+5 <= n {
					break
				}
				if err != nil || n >= len(buf) {
					break
				}
			}
			if n == 0 {
				return
			}
			out := filepath.Join(outDir, os.Getenv("CAPTURE_NAME")+".bin")
			os.WriteFile(out, buf[:n], 0o644)
			fmt.Printf("captured %d bytes -> %s\n", n, out)
		}(conn)
	}
}
GO

# build the sink once: `go run` per fingerprint is a compile per fingerprint
(cd "$WORK" && go build -o "$BIN" ./sink.go) || exit 1

run_one() {
  local fp="$1" name="$2"
  cat > "$WORK/client.json" <<JSON
{
  "log": {"level": "error"},
  "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": $SOCKS_PORT}],
  "outbounds": [{
    "type": "vless", "tag": "out",
    "server": "127.0.0.1", "server_port": $PORT,
    "uuid": "00000000-0000-0000-0000-000000000001",
    "tls": {"enabled": true, "server_name": "www.gstatic.com",
            "utls": {"enabled": true, "fingerprint": "$fp"}}
  }],
  "route": {"rules": [], "final": "out"}
}
JSON
  CAPTURE_NAME="$name" "$BIN" "$OUT" "$PORT" >/dev/null 2>&1 &
  local sink=$!
  sleep 1
  "$REF" run -c "$WORK/client.json" >/dev/null 2>&1 &
  local ref_pid=$!
  sleep 2
  curl --socks5-hostname "127.0.0.1:$SOCKS_PORT" https://www.gstatic.com/ \
       -o /dev/null -s -m 5 --connect-timeout 3 >/dev/null 2>&1 || true
  sleep 1
  kill "$ref_pid" "$sink" 2>/dev/null || true
  wait "$ref_pid" 2>/dev/null || true
  wait "$sink" 2>/dev/null || true
  echo "$name: $(stat -c%s "$OUT/$name.bin" 2>/dev/null || echo missing) bytes"
}

for fp in chrome chrome_psk chrome_psk_shuffle chrome_padding_psk_shuffle \
          chrome_pq chrome_pq_psk firefox edge safari 360 qq ios android; do
  run_one "$fp" "$fp"
done
