#!/usr/bin/env bash
# Our REALITY client against the reference's REALITY server.
#
# This is the gate that says the constants are right rather than merely
# self-consistent: the session id seal, the auth key and the version, time and
# short id inside it are things we can check against our own arithmetic
# (crates/core-tls/tests/handshake_e2e.rs), but only a real server confirms the
# server agrees with that arithmetic.
#
# Three parties, because REALITY is three:
#
#   echo     the thing at the far end, so bytes moving is not the same claim as
#            a handshake completing
#   server   the reference terminating REALITY
#   decoy    a real site behind it -- a REALITY server does not invent a
#            certificate, it borrows the decoy's ServerHello and chain, and the
#            client has to be able to verify the result
#
# The decoy is a real site (www.gstatic.com) rather than something local, and that
# is not a shortcut. Go's crypto/tls server answers a 32-byte legacy session id
# with a *different* random 32-byte one, for Chrome compatibility -- and every
# uTLS client, the reference included, refuses a ServerHello that does not echo
# it ("server did not echo the legacy session ID"). A real front end echoes it,
# so a local Go decoy cannot play this part at all. The cost is that this spike
# needs the network, which the Docker gate has by construction.
#
# The control is the reference's own REALITY client against the same server: if
# that fails too, the stand is what is wrong, not our client.
set -uo pipefail

OUT="${1:?usage: run.sh <outdir>}"
OUR="${OUR_BIN:-/cache/target/debug/tachyon-core}"
REF="${SING_BOX_REF:-sing-box-ref}"
ECHO_PORT="${ECHO_PORT:-19001}"
VLESS_PORT="${VLESS_PORT:-19002}"
SOCKS_PORT="${SOCKS_PORT:-19003}"
SNI="${SNI:-www.gstatic.com}"
DECOY="${DECOY:-www.gstatic.com}"
DECOY_PORT="${DECOY_PORT:-443}"
SHORT_ID="${SHORT_ID:-1234abcd}"

mkdir -p "$OUT"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/echo.py" <<'PY'
import socket, sys, threading
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", int(sys.argv[1])))
srv.listen(4)
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

# preflight: without the decoy there is nothing to borrow, and the failure would
# arrive ten lines later as an inscrutable handshake error
if ! curl -sS -o /dev/null --max-time 15 "https://$DECOY/generate_204" \
    && ! curl -sS -o /dev/null --max-time 15 "https://$DECOY/"; then
    echo "the decoy $DECOY is unreachable: this spike needs the network" >&2
    exit 2
fi

KEYS="$("$REF" generate reality-keypair)"
PRIVATE="$(printf '%s' "$KEYS" | sed -n 's/^PrivateKey: //p')"
PUBLIC="$(printf '%s' "$KEYS" | sed -n 's/^PublicKey: //p')"
if [ -z "$PRIVATE" ] || [ -z "$PUBLIC" ]; then
    echo "the reference did not produce a reality keypair" >&2
    exit 1
fi

# The server dialling its decoy is not a detail: RealityServer() dials the
# handshake target *before* it reads the ClientHello at all, so with no
# `handshake` server the whole handshake is refused with "failed to dial dest"
# and the verification never runs.
#
# trace, because the REALITY server logs its own verdict there: the auth key it
# derived, the version, time and short id it read out of the seal, and whether it
# accepted the connection. At warn it says only that the decoy was dialled, which
# is the same message for a wrong seal, a wrong short id and a broken hello.
cat > "$WORK/server.json" <<JSON
{
  "log": {"level": "trace", "timestamp": false},
  "inbounds": [{
    "type": "vless", "tag": "in", "listen": "127.0.0.1", "listen_port": $VLESS_PORT,
    "users": [{"uuid": "00000000-0000-0000-0000-000000000001"}],
    "tls": {
      "enabled": true,
      "server_name": "$SNI",
      "reality": {
        "enabled": true,
        "private_key": "$PRIVATE",
        "short_id": ["$SHORT_ID"],
        "handshake": {"server": "$DECOY", "server_port": $DECOY_PORT}
      }
    }
  }],
  "outbounds": [{"type": "direct", "tag": "d"}]
}
JSON

# ours: a mixed inbound in front of the same vless outbound, with the fingerprint
# and the REALITY parameters the server was just given. No `certificate`: the
# chain the server borrows is the decoy's real one, so the default roots are the
# right answer and naming a CA would only hide a genuine failure.
cat > "$WORK/client.json" <<JSON
{
  "log": {"level": "debug", "timestamp": false},
  "inbounds": [{
    "type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": $SOCKS_PORT
  }],
  "outbounds": [{
    "type": "vless", "tag": "out",
    "server": "127.0.0.1", "server_port": $VLESS_PORT,
    "uuid": "00000000-0000-0000-0000-000000000001",
    "tls": {
      "enabled": true,
      "server_name": "$SNI",
      "utls": {"enabled": true, "fingerprint": "chrome"},
      "reality": {"enabled": true, "public_key": "$PUBLIC", "short_id": "$SHORT_ID"}
    }
  }],
  "route": {"final": "out"}
}
JSON

# the control: the reference's own REALITY client, no inbound of ours in the way
cat > "$WORK/refclient.json" <<JSON
{
  "log": {"level": "warn", "timestamp": false},
  "outbounds": [{
    "type": "vless", "tag": "out",
    "server": "127.0.0.1", "server_port": $VLESS_PORT,
    "uuid": "00000000-0000-0000-0000-000000000001",
    "tls": {
      "enabled": true,
      "server_name": "$SNI",
      "utls": {"enabled": true, "fingerprint": "chrome"},
      "reality": {"enabled": true, "public_key": "$PUBLIC", "short_id": "$SHORT_ID"}
    }
  }],
  "route": {"final": "out"}
}
JSON

for cfg in server client refclient; do
    if ! "$REF" check -c "$WORK/$cfg.json" > "$OUT/$cfg-check.log" 2>&1; then
        echo "the reference refuses $cfg.json:" >&2
        cat "$OUT/$cfg-check.log" >&2
        exit 1
    fi
done
if ! "$OUR" check -c "$WORK/client.json" > "$OUT/our-check.log" 2>&1; then
    echo "we refuse our own reality config:" >&2
    cat "$OUT/our-check.log" >&2
    exit 1
fi

python3 "$WORK/echo.py" "$ECHO_PORT" > "$OUT/echo.log" 2>&1 &
ECHO=$!
"$REF" run -c "$WORK/server.json" > "$OUT/server.log" 2>&1 &
SERVER=$!
"$OUR" run -c "$WORK/client.json" > "$OUT/client.log" 2>&1 &
CLIENT=$!
sleep 3

BODY=$(curl --socks5-hostname "127.0.0.1:$SOCKS_PORT" --max-time 15 \
    --data-binary 'reality-through' http://127.0.0.1:$ECHO_PORT/ 2>"$OUT/curl.log")
STATUS=$?

# the control, on the same server, short id and decoy
timeout 20 "$REF" tools connect -c "$WORK/refclient.json" -o out "127.0.0.1:$ECHO_PORT" \
    > "$OUT/control.log" 2>&1
CONTROL=$?

kill "$CLIENT" "$SERVER" "$ECHO" 2>/dev/null
wait "$CLIENT" "$SERVER" "$ECHO" 2>/dev/null

# what the server made of our hello
VERDICT=$(grep -c "hs.c.conn == conn: true" "$OUT/server.log" 2>/dev/null || echo 0)

echo "curl exit: $STATUS"
echo "body: $BODY"
echo "control exit: $CONTROL"
echo "server accepted: $VERDICT of 2"
if [ "$STATUS" -eq 0 ] && [ "$BODY" = "echo:reality-through" ]; then
    echo "PASS  a real REALITY server took our handshake and our traffic"
    exit 0
fi
if [ "$CONTROL" -ne 0 ]; then
    echo "FAIL  the reference does not accept its own client here either: the stand" >&2
    echo "      is what is wrong -- control.log, server.log" >&2
    exit 2
fi
if [ "${VERDICT:-0}" -lt 2 ]; then
    echo "FAIL  the reference accepts its own client and refuses ours" >&2
    grep -iE "REALITY remoteAddr|error" "$OUT/server.log" | cut -c1-200 | head -20 >&2
    exit 3
fi
echo "FAIL  the server accepted us and the traffic still did not come back" >&2
for log in client curl server; do
    echo "--- $log" >&2
    tail -12 "$OUT/$log.log" >&2 2>/dev/null
done
exit 1
