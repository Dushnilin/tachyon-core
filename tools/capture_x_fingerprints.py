"""Capture Sing-Box X ClientHellos using only loopback sockets.

Usage: python3 tools/capture_x_fingerprints.py /path/to/sing-box-x
"""
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

out = pathlib.Path("tests/spikes/clienthello/captures-sing-box-x")
out.mkdir(parents=True, exist_ok=True)


def receive(conn, count):
    data = b""
    while len(data) < count:
        chunk = conn.recv(count - len(data))
        if not chunk:
            raise RuntimeError("short read")
        data += chunk
    return data


for name in ["chrome", "firefox", "safari"]:
    with socket.socket() as sink, socket.socket() as reserve:
        sink.bind(("127.0.0.1", 0))
        sink.listen()
        sink.settimeout(5)
        port = sink.getsockname()[1]
        reserve.bind(("127.0.0.1", 0))
        socks = reserve.getsockname()[1]
        reserve.close()
        config = {
            "log": {"level": "error"},
            "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": socks}],
            "outbounds": [{"type": "vless", "tag": "out", "server": "127.0.0.1",
                           "server_port": port, "uuid": "00000000-0000-0000-0000-000000000001",
                           "tls": {"enabled": True, "server_name": "www.gstatic.com",
                                   "utls": {"enabled": True, "fingerprint": name}}}],
            "route": {"final": "out"},
        }
        with tempfile.TemporaryDirectory() as work:
            path = pathlib.Path(work) / "config.json"
            path.write_text(json.dumps(config))
            process = subprocess.Popen([sys.argv[1], "run", "-c", str(path)],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                client = None
                for _ in range(100):
                    try:
                        client = socket.create_connection(("127.0.0.1", socks), timeout=2)
                        break
                    except OSError:
                        if process.poll() is not None:
                            raise RuntimeError(process.stderr.read().decode())
                        time.sleep(0.05)
                if client is None:
                    raise RuntimeError("proxy startup timeout")
                with client:
                    client.sendall(b"\x05\x01\x00")
                    assert receive(client, 2) == b"\x05\x00"
                    client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + port.to_bytes(2, "big"))
                    with sink.accept()[0] as conn:
                        conn.settimeout(5)
                        header = receive(conn, 5)
                        data = header + receive(conn, int.from_bytes(header[3:5], "big"))
                        (out / (name + ".bin")).write_bytes(data)
                        print(name, len(data))
            finally:
                process.terminate()
                process.communicate(timeout=5)
