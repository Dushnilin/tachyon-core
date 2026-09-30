#!/usr/bin/env bash
# Our XHTTP client against a real Xray server.
#
# The REALITY spike stands the reference up as the server because it ships in the
# repository; for XHTTP the arbiter is Xray itself, since that is what every
# provider runs and its request matching *is* the specification. So this expects
# an Xray binary (XRAY_BIN) and needs nothing else: no network, no subscription,
# no provider.
#
# `PLAIN=1` turns REALITY off and puts an ordinary certificate in its place, which
# is how a problem with our hello or our XHTTP session gets told apart from a
# problem with the REALITY handshake: same server, same transport, same probe, one
# variable.
set -uo pipefail

OUT="${1:?usage: run.sh <outdir>}"
OUR="${OUR_BIN:?OUR_BIN=<our tachyon-core binary>}"
XRAY="${XRAY_BIN:-xray}"
SERVER_PORT="${SERVER_PORT:-19902}"
ECHO_PORT="${ECHO_PORT:-19901}"
DECOY_PORT="${DECOY_PORT:-19904}"
SOCKS_PORT="${SOCKS_PORT:-19903}"
PATH_X="${PATH_X:-/xh}"
SHORT_ID="${SHORT_ID:-6ba85179e30d4fc3}"
SNI="${SNI:-localhost}"
UUID="${UUID:-00000000-0000-0000-0000-000000000001}"
PLAIN="${PLAIN:-0}"

# Windows names it python, everyone else python3, and this stand has to run in
# both. Asking each candidate whether it actually runs matters: Windows ships a
# `python3` App Execution Alias that is on PATH and prints the Store notice, and
# `command -v` is perfectly happy with it.
PY="${PYTHON:-}"
if [ -z "$PY" ]; then
    for candidate in python3 python; do
        if command -v "$candidate" > /dev/null 2>&1 && "$candidate" --version > /dev/null 2>&1; then
            PY="$candidate"
            break
        fi
    done
fi
if [ -z "$PY" ]; then
    echo "no working python: set PYTHON=..." >&2
    exit 2
fi
if ! command -v "$XRAY" > /dev/null 2>&1 && [ ! -x "$XRAY" ]; then
    echo "no Xray binary: set XRAY_BIN" >&2
    exit 2
fi

mkdir -p "$OUT"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/echo.py" <<'PY'
import socket, sys, threading
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", int(sys.argv[1])))
srv.listen(8)
def serve(conn):
    with conn:
        while True:
            data = conn.recv(4096)
            if not data:
                return
            conn.sendall(b"echo:" + data)
while True:
    conn, _ = srv.accept()
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
PY

cat > "$WORK/probe.py" <<'PY'
import socket, struct, sys
proxy, port, payload = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3].encode()
s = socket.create_connection(("127.0.0.1", proxy), timeout=15)
s.settimeout(15)
s.sendall(b"\x05\x01\x00")
if s.recv(2) != b"\x05\x00":
    sys.exit("no socks greeting")
h = "127.0.0.1"
s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(h) + struct.pack(">H", port))
reply = s.recv(10)
if len(reply) < 2 or reply[1] != 0:
    sys.exit("socks connect refused: %r" % (reply,))
s.sendall(payload)
data = b""
try:
    while len(data) < len(payload) + 64:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
except socket.timeout:
    pass
# The verdict is a single word and the bytes come back escaped: a Windows console
# is cp1251 and the echo's bytes are not encodable there, so a stand that has to
# report a failure cannot print them raw.
if data == b"echo:" + payload:
    print("OK")
    sys.exit(0)
print("GOT " + ascii(data.decode("latin1")))
sys.exit(1)
PY

# XMUX=1 gives both sides the xmux settings a provider's node carries, which is
# where a client that works against a bare server can still fail
if [ "${LOOPBACK:-0}" = "1" ]; then
    FREEDOM="{\"protocol\": \"freedom\", \"tag\": \"direct\", \"settings\": {\"finalRules\": [{\"action\": \"allow\", \"ip\": [\"127.0.0.0/8\", \"::1/128\"]}]}}"
else
    FREEDOM="{\"protocol\": \"freedom\", \"tag\": \"direct\"}"
fi

if [ "${XMUX:-0}" = "1" ]; then
    XMUX_SERVER=', "scMaxEachPostBytes": "16384-32768", "xPaddingBytes": "100-1000", "xmuxSettings": {"maxConcurrency": "1-4", "cMaxReuseTimes": "32-64", "hMaxRequestTimes": "200-400", "hMaxReusableSecs": "120-300", "hKeepAlivePeriod": 20}'
    XMUX_CLIENT=', "sc_max_each_post_bytes": "16384-32768", "x_padding_bytes": "100-1000", "xmux": {"max_concurrency": "1-4", "c_max_reuse_times": "32-64", "h_max_request_times": "200-400", "h_max_reusable_secs": "120-300", "h_keep_alive_period": 20}'
else
    XMUX_SERVER=""
    XMUX_CLIENT=""
fi

if [ "$PLAIN" = "1" ]; then
    SECURITY=tls
    ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
    # Xray is a Windows program on a Windows host and gets a POSIX path from a
    # Git-bash shell, which it cannot open. cygpath is the translator; on a real
    # Unix host there is nothing to translate.
    if command -v cygpath > /dev/null 2>&1; then
        ROOT="$(cygpath -m "$ROOT")"
    fi
    CERTS="$ROOT/tests/golden/certs"
    # Xray's own shape for a certificate, which is not sing-box's
    TLS_BLOCK="\"tlsSettings\": {\"serverName\": \"$SNI\", \"certificates\": [{\"usage\": \"encipherment\", \"certificateFile\": \"$CERTS/localhost.crt\", \"keyFile\": \"$CERTS/localhost.key\"}]}"
    CLIENT_TLS="{\"enabled\": true, \"server_name\": \"$SNI\", \"insecure\": true, \"utls\": {\"enabled\": true, \"fingerprint\": \"chrome\"}}"
else
    # Xray's own keypair, so the stand and the client cannot disagree about it
    KEYS="$("$XRAY" x25519)"
    PRIVATE="$(printf '%s' "$KEYS" | sed -n 's/^PrivateKey: //p')"
    # Xray labelled this "PublicKey" until v26 and "Password (PublicKey)" after,
    # which is the sort of thing that costs an afternoon
    PUBLIC="$(printf '%s' "$KEYS" | sed -n 's/^Password (PublicKey): //p; s/^Password: //p; s/^PublicKey: //p')"
    if [ -z "$PRIVATE" ] || [ -z "$PUBLIC" ]; then
        echo "xray did not produce a keypair: $KEYS" >&2
        exit 2
    fi
    SECURITY=reality
    ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
    if command -v cygpath > /dev/null 2>&1; then
        ROOT="$(cygpath -m "$ROOT")"
    fi
    CERTS="$ROOT/tests/golden/certs"
    # dest is the site REALITY hides behind, and it has to be a real TLS server:
    # a client the server does not accept is handed to it, so pointing dest at
    # something that cannot speak TLS turns "we were not accepted" into a hang
    # instead of into a certificate the client can name. Xray's own second
    # inbound plays the part.
    TLS_BLOCK="\"realitySettings\": {\"show\": false, \"dest\": \"127.0.0.1:$DECOY_PORT\", \"xver\": 0, \"serverNames\": [\"$SNI\"], \"privateKey\": \"$PRIVATE\", \"shortIds\": [\"$SHORT_ID\"]}"
    CLIENT_TLS="{\"enabled\": true, \"server_name\": \"$SNI\", \"utls\": {\"enabled\": true, \"fingerprint\": \"chrome\"}, \"reality\": {\"enabled\": true, \"public_key\": \"$PUBLIC\", \"short_id\": \"$SHORT_ID\"}}"
fi

cat > "$WORK/server.json" <<JSON
{
  "log": {"loglevel": "debug"},
  "inbounds": [{
    "listen": "127.0.0.1",
    "port": $SERVER_PORT,
    "protocol": "vless",
    "settings": {"clients": [{"id": "$UUID"}], "decryption": "none"},
    "streamSettings": {
      "network": "xhttp",
      "xhttpSettings": {"path": "$PATH_X", "mode": "packet-up", "host": "$SNI"$XMUX_SERVER},
      "security": "$SECURITY",
      $TLS_BLOCK
    }
  }],
  "outbounds": [$FREEDOM]
}
JSON

# the decoy site REALITY hides behind, when there is one: an ordinary TLS inbound
# in the same Xray, so the stand stays one process and the fallback path has
# something real to talk to
if [ "$PLAIN" != "1" ]; then
cat > "$WORK/decoy.json" <<JSON
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "listen": "127.0.0.1",
    "port": $DECOY_PORT,
    "protocol": "vless",
    "settings": {"clients": [{"id": "$UUID"}], "decryption": "none"},
    "streamSettings": {
      "security": "tls",
      "tlsSettings": {
        "serverName": "$SNI",
        "certificates": [{"usage": "encipherment", "certificateFile": "$CERTS/localhost.crt", "keyFile": "$CERTS/localhost.key"}]
      }
    }
  }],
  "outbounds": [$FREEDOM]
}
JSON
fi

cat > "$WORK/client.json" <<JSON
{
  "log": {"level": "debug", "timestamp": false},
  "inbounds": [{
    "type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": $SOCKS_PORT
  }],
  "outbounds": [{
    "type": "vless", "tag": "out",
    "server": "127.0.0.1", "server_port": $SERVER_PORT,
    "uuid": "$UUID",
    "tls": $CLIENT_TLS,
    "transport": {"type": "xhttp", "path": "$PATH_X", "host": "$SNI", "mode": "packet-up"$XMUX_CLIENT}
  }],
  "route": {"final": "out"}
}
JSON

if ! "$OUR" check -c "$WORK/client.json" > "$OUT/client-check.log" 2>&1; then
    echo "we refuse our own config:" >&2
    cat "$OUT/client-check.log" >&2
    exit 1
fi

"$PY" "$WORK/echo.py" "$ECHO_PORT" > "$OUT/echo.log" 2>&1 &
ECHO=$!
sleep 1
if [ "$PLAIN" != "1" ]; then
    "$XRAY" run -c "$WORK/decoy.json" > "$OUT/decoy.log" 2>&1 &
    DECOY=$!
else
    DECOY=""
fi
"$XRAY" run -c "$WORK/server.json" > "$OUT/server.log" 2>&1 &
SERVER=$!
"$OUR" run -c "$WORK/client.json" > "$OUT/client.log" 2>&1 &
CLIENT=$!
sleep 3

BODY=$("$PY" "$WORK/probe.py" "$SOCKS_PORT" "$ECHO_PORT" 'xhttp-through' 2>"$OUT/probe.log")
STATUS=$?

kill "$CLIENT" "$SERVER" "$ECHO" $DECOY 2>/dev/null
wait "$CLIENT" "$SERVER" "$ECHO" $DECOY 2>/dev/null

echo "probe exit: $STATUS"
echo "body: $BODY"
if [ "$STATUS" -eq 0 ] && [ "$BODY" = "OK" ]; then
    echo "PASS  a real Xray server took our XHTTP session and our traffic"
    exit 0
fi
echo "FAIL  the traffic did not come back" >&2
for log in client server probe; do
    echo "--- $log" >&2
    tail -15 "$OUT/$log.log" >&2 2>/dev/null
done
exit 1
