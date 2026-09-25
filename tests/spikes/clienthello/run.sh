#!/usr/bin/env bash
# Capture ClientHello from sing-box-lx with utls chrome (F0 spike B, ADR-0004).
set -euo pipefail
cd "$(dirname "$0")"
trap 'kill $(jobs -p) 2>/dev/null || true' EXIT

(cd capture && go run . ../chrome_lx8.bin) &
CAPTURE_PID=$!
sleep 2

SING_BOX="${SING_BOX:-/tmp/sbx-ref/sing-box-1.14.2-lx.3-windows-amd64/sing-box.exe}"
"$SING_BOX" run -c client.json &
sleep 2

curl --socks5-hostname 127.0.0.1:21080 https://www.gstatic.com/ -o /dev/null -s -m 5 --connect-timeout 3 || true
wait $CAPTURE_PID || true
sleep 1

if [[ -f chrome_lx8.bin ]]; then
  echo "captured $(stat -c%s chrome_lx8.bin 2>/dev/null || stat -f%z chrome_lx8.bin) bytes"
  hexdump -C chrome_lx8.bin | head -20
else
  echo "capture failed" >&2
  exit 1
fi
