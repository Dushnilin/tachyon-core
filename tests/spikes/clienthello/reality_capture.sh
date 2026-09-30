#!/usr/bin/env bash
# What does the reference send for a REALITY client with each fingerprint?
# The unusable ones (ios/edge/qq/android/360) are ~200-500 byte hellos that a
# REALITY server cannot verify; xray replaces them with chrome. This captures
# the bytes so the answer is the reference's, not a guess.
set -uo pipefail
OUT="${1:?usage: reality_capture.sh <outdir>}"
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
			out := filepath.Join(outDir, os.Getenv("CAPTURE_NAME")+"-"+strconv.Itoa(index)+".bin")
			os.WriteFile(out, buf[:n], 0o644)
		}(conn, seen)
		seen++
	}
}
GO
(cd "$WORK" && go build -o sink ./sink.go) || exit 1

run_one() {
  local fp="$1" name="$2"
  cat > "$WORK/client.json" <<JSON
{
  "log": {"level": "debug"},
  "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": $SOCKS_PORT}],
  "outbounds": [{
    "type": "vless", "tag": "out",
    "server": "127.0.0.1", "server_port": $PORT,
    "uuid": "00000000-0000-0000-0000-000000000001",
    "tls": {
      "enabled": true, "server_name": "www.gstatic.com",
      "utls": {"enabled": true, "fingerprint": "$fp"},
      "reality": {
        "enabled": true,
        "public_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
        "short_id": "1234abcd"
      }
    }
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
  echo "$fp: $(stat -c%s "$OUT/$name-0.bin" 2>/dev/null || echo missing) bytes"
}

for fp in chrome firefox safari ios edge qq android 360; do
  run_one "$fp" "reality-$fp"
done
