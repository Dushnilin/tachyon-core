#!/usr/bin/env python3
"""Benchmark matrix: tachyon-core vs sing-box vs Xray vs Mihomo.

    load/sink  --SOCKS-->  proxy under test  --protocol-->  proxy server  -->  sink

One topology for every engine, otherwise the comparison is worth nothing. The
proxy under test plays the router and gets a fixed CPU budget (2 cores by
default, `-Cores N` to change it, TACHYON_WORKERS/GOMAXPROCS follow). The
protocol server and the load generator get the rest of the box, so the engine
under test is the only thing that can saturate.

The server side is deliberately the same binary for everybody. sing-box-lx
cannot listen for reality, shadowtls, wireguard, masque, mieru or snell at all
(`unknown inbound type`), so tachyon-core serves -- it is the only engine here
that speaks the whole matrix. That does not bias the client numbers: the server
gets twice the cores and never becomes the bottleneck.

Reports: --out JSON, --html HTML, --md Markdown.
"""

import argparse
import asyncio
import base64
import hashlib
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

SINK_PORT = 45001
PROXY_PORT = 45002
SERVER_PORT = 21200
CHUNK = 1 << 20

MODE_HOLD, MODE_ECHO, MODE_SOURCE = b"H", b"E", b"S"

UUID_STR = "b831381d-6324-4d53-ad4f-8cda48b30811"
SHADOWTLS_PASS = "bench-shadowtls-pass"
MIERU_PASS = "bench-mieru-pass"
SNELL_PSK = "0123456789abcdef"

ENGINES = ["tachyon", "sing-box", "xray", "mihomo"]
LABELS = {"tachyon": "tachyon-core", "sing-box": "sing-box-lx",
          "xray": "Xray", "mihomo": "Mihomo"}


# --------------------------------------------------------------------- certs
def pem_to_der(pem):
    """xray pins the SHA256 of the DER cert, so unwrap the PEM first."""
    body = b"".join(l for l in pem.splitlines() if not l.startswith(b"-----"))
    return base64.b64decode(body)


def make_certs(d):
    """Two certs: `cert.pem` for our own TLS, `reality.pem` for REALITY, which
    has to carry the SNI of the site it pretends to be."""
    crt = os.path.join(d, "cert.pem")
    key = os.path.join(d, "key.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", crt, "-days", "2", "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
        check=True, capture_output=True,
    )
    rcrt = os.path.join(d, "reality.pem")
    rkey = os.path.join(d, "reality-key.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", rkey, "-out", rcrt, "-days", "2", "-subj", "/CN=www.microsoft.com",
         "-addext", "subjectAltName=DNS:www.microsoft.com"],
        check=True, capture_output=True,
    )
    with open(crt, "rb") as f:
        der = pem_to_der(f.read())
    return {"cert": crt, "key": key, "reality": rcrt, "reality_key": rkey,
            "pin": base64.b64encode(hashlib.sha256(der).digest()).decode()}


# ------------------------------------------------------------------- the sink
def run_sink(cpus):
    if cpus and hasattr(os, "sched_setaffinity"):
        os.sched_setaffinity(0, cpus)

    async def handle(r, w):
        try:
            mode = await r.readexactly(1)
            if mode == MODE_ECHO:
                while True:
                    w.write(await r.readexactly(64))
                    await w.drain()
            elif mode == MODE_SOURCE:
                buf = b"\0" * CHUNK
                while True:
                    w.write(buf)
                    await w.drain()
            else:
                while await r.read(CHUNK):
                    pass
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            w.close()

    async def main():
        srv = await asyncio.start_server(handle, "127.0.0.1", SINK_PORT,
                                         backlog=4096)
        async with srv:
            await srv.serve_forever()

    asyncio.run(main())


# ------------------------------------------------------------------ plumbing
def recvn(s, n):
    out = b""
    while len(out) < n:
        chunk = s.recv(n - len(out))
        if not chunk:
            raise ConnectionError("eof")
        out += chunk
    return out


def wait_listen(port, proc=None, timeout=20):
    end = time.perf_counter() + timeout
    while time.perf_counter() < end:
        if proc is not None and proc.poll() is not None:
            raise RuntimeError("process died on startup")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"nothing listening on {port}")


def wait_port_free(port, timeout=20):
    end = time.perf_counter() + timeout
    while time.perf_counter() < end:
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
            return
        except OSError:
            time.sleep(0.1)
        finally:
            s.close()


UDP_PROTOCOLS = ("hysteria2", "tuic")


def wait_server(port, proc, case):
    """QUIC protocols listen on UDP, so a TCP connect would never succeed."""
    if case["server"]["type"] in UDP_PROTOCOLS:
        time.sleep(0.8)
        if proc.poll() is not None:
            raise RuntimeError("server died on startup")
        return
    wait_listen(port, proc)


def pin(cpus):
    if cpus and hasattr(os, "sched_setaffinity"):
        return lambda: os.sched_setaffinity(0, cpus)
    return None


def socks_connect(timeout=15, retries=6):
    last = None
    s = None
    for _ in range(retries):
        try:
            s = socket.create_connection(("127.0.0.1", PROXY_PORT), timeout=timeout)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.sendall(b"\x05\x01\x00")
            assert recvn(s, 2) == b"\x05\x00", "socks auth failed"
            s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1")
                      + struct.pack(">H", SINK_PORT))
            reply = recvn(s, 10)
            assert reply[1] == 0, "socks connect refused: %r" % reply
            return s
        except Exception as e:
            last = e
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass
            time.sleep(0.15)
    raise last or ConnectionError("socks connect failed")


def proc_rss(pid):
    try:
        with open("/proc/%d/status" % pid) as f:
            for line in f:
                if line.startswith("VmHWM:"):
                    return int(line.split()[1]) / 1024.0
    except OSError:
        pass
    return 0.0


# ---------------------------------------------------------------- measurement
def measure_latency(rounds):
    s = socks_connect()
    s.sendall(MODE_ECHO)
    msg = b"x" * 64
    for _ in range(50):
        s.sendall(msg)
        recvn(s, 64)
    out = []
    for _ in range(rounds):
        t0 = time.perf_counter_ns()
        s.sendall(msg)
        if recvn(s, 64) != msg:
            raise RuntimeError("corrupted echo")
        out.append((time.perf_counter_ns() - t0) / 1000.0)
    s.close()
    out.sort()
    return out


def measure_throughput(streams, seconds):
    totals = [0] * streams
    stop = threading.Event()
    errors = []
    def worker(i):
        # xhttp needs a while to open its first POST session; a stall must not
        # condemn the cell, so reconnect and keep counting.
        for attempt in range(3):
            s = None
            try:
                s = socks_connect()
                s.settimeout(25)
                s.sendall(MODE_SOURCE)
                # warm the session before the clock starts: xhttp opens its
                # POST channel lazily and the first stall would eat the budget
                s.recv(1)
                buf = bytearray(CHUNK)
                view = memoryview(buf)
                while not stop.is_set():
                    n = s.recv_into(view)
                    if not n:
                        break
                    totals[i] += n
                return
            except (socket.timeout, TimeoutError):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass
                continue
            except Exception as e:
                errors.append(repr(e))
                return

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(streams)]
    for t in threads:
        t.start()
    # let every worker finish its handshake so the timed window only covers
    # steady-state transfer
    time.sleep(0.3)
    t0 = time.perf_counter()
    time.sleep(seconds)
    stop.set()
    for t in threads:
        t.join(timeout=15)
    elapsed = time.perf_counter() - t0

    if errors:
        raise RuntimeError("; ".join(errors[:3]))
    moved = sum(totals)
    if not moved:
        raise RuntimeError("no bytes moved")
    return moved / ((1 << 30) / elapsed)


# --------------------------------------------------------------------- cases
def build_cases(C):
    crt, key = C["cert"], C["key"]
    # xray dropped allowInsecure and offers no private-CA flag, so it pins
    PIN = C["pin"]

    def tls(server_name="localhost", insecure=False):
        t = {"enabled": True, "server_name": server_name,
             "certificate_path": crt, "key_path": key}
        if insecure:
            t["insecure"] = True
        return t

    def ctls(server_name="localhost"):
        return {"enabled": True, "server_name": server_name, "insecure": True}

    def reality():
        # The server side still wants a certificate on file even though the
        # handshake is REALITY's own; reuse the throwaway one.
        return {
            "enabled": True,
            "server_name": "www.microsoft.com",
            "certificate_path": C["reality"],
            "key_path": C["reality_key"],
            "utls": {"enabled": True, "fingerprint": "chrome"},
            "reality": {
                "enabled": True,
                "private_key": "oCaUfPIMtXX3FzD28bXIwpTdRYwTqkZSPk-0B_Pagmo",
                "short_id": ["0123456789abcdef"],
            },
        }

    def reality_client():
        return {
            "enabled": True,
            "server_name": "www.microsoft.com",
            "utls": {"enabled": True, "fingerprint": "chrome"},
            "insecure": True,
            "reality": {
                "enabled": True,
                "public_key": "VKTZLFxC7gGIMnxE4HfTYOZO3lMXpLRRTk3jSBdYelI",
                "short_id": "0123456789abcdef",
            },
        }

    out = []

    def add(cid, name, group, srv, sb_c, x_c, mh_c, extra_out=(), server=""):
        out.append({"id": cid, "name": name, "group": group, "server": srv,
                    "sb": sb_c, "xray": x_c, "mihomo": mh_c,
                    "extra_out": list(extra_out), "server_bin": server})

    ss_pw = "bench-pass"
    ss2022_pw = "MTIzNDU2Nzg5MDEyMzQ1Ng=="

    # --- Shadowsocks ---
    for tag, method, nice in (
            ("ss-aes-128-gcm", "aes-128-gcm", "Shadowsocks AES-128-GCM"),
            ("ss-aes-256-gcm", "aes-256-gcm", "Shadowsocks AES-256-GCM"),
            ("ss-chacha20-poly1305", "chacha20-ietf-poly1305",
             "Shadowsocks ChaCha20-Poly1305")):
        add(tag, nice, "Shadowsocks",
            {"type": "shadowsocks", "method": method, "password": ss_pw},
            {"type": "shadowsocks", "server": "127.0.0.1",
             "server_port": SERVER_PORT, "method": method, "password": ss_pw},
            {"protocol": "shadowsocks",
             "settings": {"servers": [{"address": "127.0.0.1", "port": SERVER_PORT,
                                      "method": method, "password": ss_pw}]}},
            {"type": "ss", "cipher": method, "password": ss_pw})

    add("ss2022-aes-128-gcm", "Shadowsocks 2022 AES-128-GCM", "Shadowsocks",
        {"type": "shadowsocks", "method": "2022-blake3-aes-128-gcm",
         "password": ss2022_pw},
        {"type": "shadowsocks", "server": "127.0.0.1", "server_port": SERVER_PORT,
         "method": "2022-blake3-aes-128-gcm", "password": ss2022_pw},
        None,
        {"type": "ss", "cipher": "2022-blake3-aes-128-gcm", "password": ss2022_pw})

    # --- VMess ---
    add("vmess", "VMess", "VMess",
        {"type": "vmess", "users": [{"uuid": UUID_STR}]},
        {"type": "vmess", "server": "127.0.0.1", "server_port": SERVER_PORT,
         "uuid": UUID_STR},
        {"protocol": "vmess",
         "settings": {"vnext": [{"address": "127.0.0.1", "port": SERVER_PORT,
                                  "users": [{"id": UUID_STR, "alterId": 0}]}]}},
        {"type": "vmess", "uuid": UUID_STR, "alterId": 0, "cipher": "auto"})

    add("vmess-tls", "VMess + TLS", "VMess",
        {"type": "vmess", "users": [{"uuid": UUID_STR}], "tls": tls()},
        {"type": "vmess", "server": "127.0.0.1", "server_port": SERVER_PORT,
         "uuid": UUID_STR, "tls": ctls()},
        {"protocol": "vmess", "settings": {"vnext": [{"address": "127.0.0.1", "port": SERVER_PORT,
                                  "users": [{"id": UUID_STR, "alterId": 0}]}]},
         "streamSettings": {"security": "tls",
                            "tlsSettings": {"serverName": "localhost", "pinnedPeerCertificateChainSha256": [PIN],
                                            "allowInsecure": True}}},
        {"type": "vmess", "uuid": UUID_STR, "alterId": 0, "cipher": "auto",
         "tls": True, "skip-cert-verify": True, "servername": "localhost"})

    add("vmess-ws-tls", "VMess + WS + TLS", "VMess",
        {"type": "vmess", "users": [{"uuid": UUID_STR}], "tls": tls(),
         "transport": {"type": "ws", "path": "/ws"}},
        {"type": "vmess", "server": "127.0.0.1", "server_port": SERVER_PORT,
         "uuid": UUID_STR, "tls": ctls(),
         "transport": {"type": "ws", "path": "/ws"}},
        {"protocol": "vmess", "settings": {"vnext": [{"address": "127.0.0.1", "port": SERVER_PORT,
                                  "users": [{"id": UUID_STR, "alterId": 0}]}]},
         "streamSettings": {"network": "ws", "security": "tls",
                            "wsSettings": {"path": "/ws"},
                            "tlsSettings": {"serverName": "localhost", "pinnedPeerCertificateChainSha256": [PIN],
                                            "allowInsecure": True}}},
        None)

    add("vmess-grpc-tls", "VMess + gRPC + TLS", "VMess",
        {"type": "vmess", "users": [{"uuid": UUID_STR}], "tls": tls(),
         "transport": {"type": "grpc", "service_name": "grpc"}},
        {"type": "vmess", "server": "127.0.0.1", "server_port": SERVER_PORT,
         "uuid": UUID_STR, "tls": ctls(),
         "transport": {"type": "grpc", "service_name": "grpc"}},
        {"protocol": "vmess", "settings": {"vnext": [{"address": "127.0.0.1", "port": SERVER_PORT,
                                  "users": [{"id": UUID_STR, "alterId": 0}]}]},
         "streamSettings": {"network": "grpc", "security": "tls",
                            "grpcSettings": {"serviceName": "grpc"},
                            "tlsSettings": {"serverName": "localhost", "pinnedPeerCertificateChainSha256": [PIN],
                                            "allowInsecure": True}}},
        None)

    # --- VLESS ---
    add("vless", "VLESS", "VLESS",
        {"type": "vless", "users": [{"uuid": UUID_STR}]},
        {"type": "vless", "server": "127.0.0.1", "server_port": SERVER_PORT,
         "uuid": UUID_STR},
        {"protocol": "vless",
         "settings": {"vnext": [{"address": "127.0.0.1", "port": SERVER_PORT,
                                 "users": [{"id": UUID_STR,
                                            "encryption": "none"}]}]}},
        {"type": "vless", "uuid": UUID_STR})

    add("vless-tls", "VLESS + TLS", "VLESS",
        {"type": "vless", "users": [{"uuid": UUID_STR}], "tls": tls()},
        {"type": "vless", "server": "127.0.0.1", "server_port": SERVER_PORT,
         "uuid": UUID_STR, "tls": ctls()},
        {"protocol": "vless",
         "settings": {"vnext": [{"address": "127.0.0.1", "port": SERVER_PORT,
                                 "users": [{"id": UUID_STR,
                                            "encryption": "none"}]}]},
         "streamSettings": {"security": "tls",
                            "tlsSettings": {"serverName": "localhost", "pinnedPeerCertificateChainSha256": [PIN],
                                            "allowInsecure": True}}},
        {"type": "vless", "uuid": UUID_STR, "tls": True, "skip-cert-verify": True,
         "servername": "localhost"})

    add("vless-tls-vision", "VLESS + TLS + Vision", "VLESS",
        {"type": "vless", "users": [{"uuid": UUID_STR, "flow": "xtls-rprx-vision"}],
         "tls": tls()},
        {"type": "vless", "server": "127.0.0.1", "server_port": SERVER_PORT,
         "uuid": UUID_STR, "tls": ctls(), "flow": "xtls-rprx-vision"},
        {"protocol": "vless",
         "settings": {"vnext": [{"address": "127.0.0.1", "port": SERVER_PORT,
                                 "users": [{"id": UUID_STR, "encryption": "none",
                                            "flow": "xtls-rprx-vision"}]}]},
         "streamSettings": {"security": "tls",
                            "tlsSettings": {"serverName": "localhost", "pinnedPeerCertificateChainSha256": [PIN],
                                            "allowInsecure": True}}},
        None)

    add("vless-ws-tls", "VLESS + WS + TLS", "VLESS",
        {"type": "vless", "users": [{"uuid": UUID_STR}], "tls": tls(),
         "transport": {"type": "ws", "path": "/ws"}},
        {"type": "vless", "server": "127.0.0.1", "server_port": SERVER_PORT,
         "uuid": UUID_STR, "tls": ctls(),
         "transport": {"type": "ws", "path": "/ws"}},
        {"protocol": "vless",
         "settings": {"vnext": [{"address": "127.0.0.1", "port": SERVER_PORT,
                                 "users": [{"id": UUID_STR,
                                            "encryption": "none"}]}]},
         "streamSettings": {"network": "ws", "security": "tls",
                            "wsSettings": {"path": "/ws"},
                            "tlsSettings": {"serverName": "localhost", "pinnedPeerCertificateChainSha256": [PIN],
                                            "allowInsecure": True}}},
        None)

    add("vless-grpc-tls", "VLESS + gRPC + TLS", "VLESS",
        {"type": "vless", "users": [{"uuid": UUID_STR}], "tls": tls(),
         "transport": {"type": "grpc", "service_name": "grpc"}},
        {"type": "vless", "server": "127.0.0.1", "server_port": SERVER_PORT,
         "uuid": UUID_STR, "tls": ctls(),
         "transport": {"type": "grpc", "service_name": "grpc"}},
        {"protocol": "vless",
         "settings": {"vnext": [{"address": "127.0.0.1", "port": SERVER_PORT,
                                 "users": [{"id": UUID_STR,
                                            "encryption": "none"}]}]},
         "streamSettings": {"network": "grpc", "security": "tls",
                            "grpcSettings": {"serviceName": "grpc"},
                            "tlsSettings": {"serverName": "localhost", "pinnedPeerCertificateChainSha256": [PIN],
                                            "allowInsecure": True}}},
        None)

    add("vless-httpupgrade-tls", "VLESS + HTTPUpgrade + TLS", "VLESS",
        {"type": "vless", "users": [{"uuid": UUID_STR}], "tls": tls(),
         "transport": {"type": "httpupgrade", "path": "/hu"}},
        {"type": "vless", "server": "127.0.0.1", "server_port": SERVER_PORT,
         "uuid": UUID_STR, "tls": ctls(),
         "transport": {"type": "httpupgrade", "path": "/hu"}},
        {"protocol": "vless",
         "settings": {"vnext": [{"address": "127.0.0.1", "port": SERVER_PORT,
                                 "users": [{"id": UUID_STR,
                                            "encryption": "none"}]}]},
         "streamSettings": {"network": "httpupgrade", "security": "tls",
                            "httpupgradeSettings": {"path": "/hu"},
                            "tlsSettings": {"serverName": "localhost", "pinnedPeerCertificateChainSha256": [PIN],
                                            "allowInsecure": True}}},
        None)

    add("vless-h2-tls", "VLESS + HTTP/2 + TLS", "VLESS",
        {"type": "vless", "users": [{"uuid": UUID_STR}], "tls": tls(),
         "transport": {"type": "http"}},
        {"type": "vless", "server": "127.0.0.1", "server_port": SERVER_PORT,
         "uuid": UUID_STR, "tls": ctls(), "transport": {"type": "http"}},
        {"protocol": "vless",
         "settings": {"vnext": [{"address": "127.0.0.1", "port": SERVER_PORT,
                                 "users": [{"id": UUID_STR,
                                            "encryption": "none"}]}]},
         "streamSettings": {"network": "http", "security": "tls",
                            "tlsSettings": {"serverName": "localhost", "pinnedPeerCertificateChainSha256": [PIN],
                                            "allowInsecure": True}}},
        None)

    def xhttp(mode, path="/x"):
        return {"type": "xhttp", "mode": mode, "path": path}

    def xhttp_xray(mode, path="/x"):
        return {"network": "xhttp",
                "xhttpSettings": {"mode": mode, "path": path}}

    def xhttp_case(cid, name, mode, srv_tls, cli_tls, x_tls=None):
        add(cid, name, "XHTTP",
            {"type": "vless", "users": [{"uuid": UUID_STR}], "tls": srv_tls,
             "transport": xhttp(mode)},
            {"type": "vless", "server": "127.0.0.1", "server_port": SERVER_PORT,
             "uuid": UUID_STR, "tls": cli_tls, "transport": xhttp(mode)},
            {"protocol": "vless",
             "settings": {"vnext": [{"address": "127.0.0.1", "port": SERVER_PORT,
                                     "users": [{"id": UUID_STR,
                                                "encryption": "none"}]}]},
             "streamSettings": dict({"security": "tls",
                                     "tlsSettings": x_tls or {}},
                                    **xhttp_xray(mode))},
            None)

    xhttp_case("vless-xhttp-packet-up", "VLESS + XHTTP packet-up + TLS",
               "packet-up", tls(), ctls(),
               {"serverName": "localhost"})
    xhttp_case("vless-xhttp-stream-up", "VLESS + XHTTP stream-up + TLS",
               "stream-up", tls(), ctls(),
               {"serverName": "localhost"})
    xhttp_case("vless-xhttp-auto", "VLESS + XHTTP auto + TLS",
               "auto", tls(), ctls(),
               {"serverName": "localhost"})

    add("vless-xhttp-reality", "VLESS + XHTTP + REALITY", "XHTTP",
        {"type": "vless", "users": [{"uuid": UUID_STR}], "tls": reality(),
         "transport": xhttp("packet-up")},
        {"type": "vless", "server": "127.0.0.1", "server_port": SERVER_PORT,
         "uuid": UUID_STR, "tls": reality_client(),
         "transport": xhttp("packet-up")},
        None,
        None)

    add("vless-reality", "VLESS + REALITY", "VLESS",
        {"type": "vless", "users": [{"uuid": UUID_STR}], "tls": reality()},
        {"type": "vless", "server": "127.0.0.1", "server_port": SERVER_PORT,
         "uuid": UUID_STR, "tls": reality_client()},
        {"protocol": "vless",
         "settings": {"vnext": [{"address": "127.0.0.1", "port": SERVER_PORT,
                                 "users": [{"id": UUID_STR,
                                            "encryption": "none"}]}]},
         "streamSettings": {"security": "reality",
                            "realitySettings": {
                                "serverName": "www.microsoft.com",
                                "fingerprint": "chrome",
                                "publicKey": reality_client()["reality"]["public_key"],
                                "shortId": "0123456789abcdef",
                                "spiderX": "/"}}},
        None)

    add("vless-reality-vision", "VLESS + REALITY + Vision", "VLESS",
        {"type": "vless",
         "users": [{"uuid": UUID_STR, "flow": "xtls-rprx-vision"}],
         "tls": reality()},
        {"type": "vless", "server": "127.0.0.1", "server_port": SERVER_PORT,
         "uuid": UUID_STR, "tls": reality_client(), "flow": "xtls-rprx-vision"},
        None,
        None)

    # --- Trojan ---
    add("trojan-tls", "Trojan + TLS", "Trojan",
        {"type": "trojan", "users": [{"password": "p"}], "tls": tls()},
        {"type": "trojan", "server": "127.0.0.1", "server_port": SERVER_PORT,
         "password": "p", "tls": ctls()},
        {"protocol": "trojan",
         "settings": {"servers": [{"address": "127.0.0.1", "port": SERVER_PORT,
                                   "password": "p"}]},
         "streamSettings": {"security": "tls",
                            "tlsSettings": {"serverName": "localhost", "pinnedPeerCertificateChainSha256": [PIN],
                                            "allowInsecure": True}}},
        {"type": "trojan", "password": "p", "sni": "localhost",
         "skip-cert-verify": True})

    add("trojan-ws-tls", "Trojan + WS + TLS", "Trojan",
        {"type": "trojan", "users": [{"password": "p"}], "tls": tls(),
         "transport": {"type": "ws", "path": "/ws"}},
        {"type": "trojan", "server": "127.0.0.1", "server_port": SERVER_PORT,
         "password": "p", "tls": ctls(),
         "transport": {"type": "ws", "path": "/ws"}},
        {"protocol": "trojan",
         "settings": {"servers": [{"address": "127.0.0.1", "port": SERVER_PORT,
                                   "password": "p"}]},
         "streamSettings": {"network": "ws", "security": "tls",
                            "wsSettings": {"path": "/ws"},
                            "tlsSettings": {"serverName": "localhost", "pinnedPeerCertificateChainSha256": [PIN],
                                            "allowInsecure": True}}},
        None)

    add("trojan-grpc-tls", "Trojan + gRPC + TLS", "Trojan",
        {"type": "trojan", "users": [{"password": "p"}], "tls": tls(),
         "transport": {"type": "grpc", "service_name": "grpc"}},
        {"type": "trojan", "server": "127.0.0.1", "server_port": SERVER_PORT,
         "password": "p", "tls": ctls(),
         "transport": {"type": "grpc", "service_name": "grpc"}},
        {"protocol": "trojan",
         "settings": {"servers": [{"address": "127.0.0.1", "port": SERVER_PORT,
                                   "password": "p"}]},
         "streamSettings": {"network": "grpc", "security": "tls",
                            "grpcSettings": {"serviceName": "grpc"},
                            "tlsSettings": {"serverName": "localhost", "pinnedPeerCertificateChainSha256": [PIN],
                                            "allowInsecure": True}}},
        None)

    add("trojan-reality", "Trojan + REALITY", "Trojan",
        {"type": "trojan", "users": [{"password": "p"}], "tls": reality()},
        {"type": "trojan", "server": "127.0.0.1", "server_port": SERVER_PORT,
         "password": "p", "tls": reality_client()},
        None,
        None)

    # --- QUIC ---
    add("hysteria2", "Hysteria2", "QUIC",
        {"type": "hysteria2", "users": [{"password": "p"}],
         "tls": tls(insecure=True)},
        {"type": "hysteria2", "server": "127.0.0.1", "server_port": SERVER_PORT,
         "password": "p", "tls": ctls()},
        None,
        {"type": "hysteria2", "password": "p", "sni": "localhost",
         "skip-cert-verify": True})

    add("tuic", "TUIC v5", "QUIC",
        {"type": "tuic",
         "users": [{"uuid": UUID_STR, "password": "p"}],
         "congestion_control": "bbr", "tls": tls(insecure=True)},
        {"type": "tuic", "server": "127.0.0.1", "server_port": SERVER_PORT,
         "uuid": UUID_STR, "password": "p", "congestion_control": "bbr",
         "tls": ctls()},
        None,
        None)

    # --- other TLS ---
    add("anytls", "AnyTLS", "TLS",
        {"type": "anytls", "users": [{"password": "p"}], "tls": tls()},
        {"type": "anytls", "server": "127.0.0.1", "server_port": SERVER_PORT,
         "password": "p", "tls": ctls()},
        None,
        {"type": "anytls", "password": "p", "sni": "localhost",
         "skip-cert-verify": True},
        server="sing-box")

    add("http", "HTTP proxy", "Other",
        {"type": "http", "users": [{"username": "u", "password": "p"}]},
        {"type": "http", "server": "127.0.0.1", "server_port": SERVER_PORT,
         "username": "u", "password": "p"},
        {"protocol": "http",
         "settings": {"servers": [{"address": "127.0.0.1", "port": SERVER_PORT,
                                   "users": [{"user": "u", "pass": "p"}]}]}},
        None)

    add("mieru", "Mieru", "Other",
        {"type": "mieru", "users": [{"name": "u", "password": MIERU_PASS}]},
        {"type": "mieru", "server": "127.0.0.1", "server_port": SERVER_PORT,
         "username": "u", "password": MIERU_PASS},
        None,
        None)

    return out


# ------------------------------------------------------------------ launching
def server_config(case):
    """The remote end.

    shadowtls is a wrapper, so the certificate lives on a second outbound that
    the inbound detours through; everything else terminates on the inbound.
    """
    cfg = {
        "log": {"level": "error"},
        "inbounds": [dict(case["server"], tag="in",
                          listen="127.0.0.1", listen_port=SERVER_PORT)],
        "outbounds": [{"type": "direct", "tag": "direct"}]
                    + [dict(o) for o in case.get("extra_out", ())],
        "route": {"final": "direct"},
    }
    return cfg


def check_config(bin_path, cfg_path):
    r = subprocess.run([bin_path, "check", "-c", cfg_path],
                       capture_output=True, text=True)
    if r.returncode != 0:
        msg = (r.stderr or r.stdout or "").strip().splitlines()
        return msg[-1] if msg else "check failed"
    return None


def launch_server(bin_path, case, cpus, workers):
    d = tempfile.mkdtemp(prefix="srv_")
    cfg_path = os.path.join(d, "config.json")
    with open(cfg_path, "w") as f:
        json.dump(server_config(case), f)
    bad = check_config(bin_path, cfg_path)
    if bad:
        raise RuntimeError("server config rejected: %s" % bad)
    wait_port_free(SERVER_PORT)
    env = os.environ.copy()
    if workers:
        env["GOMAXPROCS"] = str(workers)
        env["TACHYON_WORKERS"] = str(workers)
    log = open("/bench/server.log", "w")
    proc = subprocess.Popen([bin_path, "run", "-c", cfg_path],
                            stdout=log, stderr=subprocess.STDOUT,
                            env=env, preexec_fn=pin(cpus))
    try:
        wait_server(SERVER_PORT, proc, case)
    except Exception:
        proc.kill()
        log.flush()
        try:
            with open("/bench/server.log") as f:
                tail = " | ".join(f.read().strip().splitlines()[-3:])
        except OSError:
            tail = ""
        raise RuntimeError("server died: %s" % (tail or "no output"))
    log.close()
    return proc, d


def launch_client(engine, bin_path, case, cpus, workers):
    # tachyon and sing-box share the sing-box schema, so one spec serves both.
    spec = case.get("sb") if engine in ("tachyon", "sing-box") else case.get(engine)
    if not spec:
        return None, None
    d = tempfile.mkdtemp(prefix="cli_%s_" % engine)
    env = os.environ.copy()
    if workers:
        env["GOMAXPROCS"] = str(workers)
        env["TACHYON_WORKERS"] = str(workers)
    pre = pin(cpus)

    if engine in ("tachyon", "sing-box"):
        cfg = {
            "log": {"level": "error"},
            "inbounds": [{"type": "mixed", "tag": "in",
                          "listen": "127.0.0.1", "listen_port": PROXY_PORT}],
            "outbounds": [dict(spec, tag="proxy")],
            "route": {"final": "proxy"},
        }
        path = os.path.join(d, "config.json")
        with open(path, "w") as f:
            json.dump(cfg, f)
        cmd = [bin_path, "run", "-c", path]

    elif engine == "xray":
        cfg = {
            "log": {"loglevel": "error"},
            "inbounds": [{"listen": "127.0.0.1", "port": PROXY_PORT,
                          "protocol": "socks",
                          "settings": {"auth": "noauth", "udp": False}}],
            "outbounds": [dict(spec, tag="proxy"),
                          {"protocol": "freedom", "tag": "direct"}],
        }
        path = os.path.join(d, "config.json")
        with open(path, "w") as f:
            json.dump(cfg, f)
        cmd = [bin_path, "run", "-c", path]

    else:  # mihomo
        proxy = dict(spec, name="proxy", server="127.0.0.1", port=SERVER_PORT)
        lines = ["mixed-port: %d" % PROXY_PORT, "mode: rule",
                 "log-level: silent", "ipv6: false",
                 'external-controller: ""', "proxies:", "  - name: proxy"]
        for k, v in proxy.items():
            if k == "name":
                continue
            if isinstance(v, bool):
                lines.append("    %s: %s" % (k, "true" if v else "false"))
            else:
                lines.append("    %s: %s" % (k, v))
        lines += ["rules:", "  - MATCH,proxy"]
        path = os.path.join(d, "config.yaml")
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")
        cmd = [bin_path, "-d", d, "-f", path]

    wait_port_free(PROXY_PORT)
    logname = "/bench/client-%s.log" % engine
    log = open(logname, "w")
    proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT,
                            env=env, preexec_fn=pre)
    try:
        wait_listen(PROXY_PORT, proc)
    except Exception:
        proc.kill()
        log.flush()
        try:
            with open(logname) as f:
                tail = " | ".join(f.read().strip().splitlines()[-3:])
        except OSError:
            tail = ""
        raise RuntimeError("client died: %s" % (tail or "no output"))
    time.sleep(0.4)
    return proc, d



# -------------------------------------------------------------------- reports
def winners(results):
    wins = {e: 0 for e in ENGINES}
    for r in results:
        best, bv = None, 0.0
        for eng in ENGINES:
            c = r.get(eng)
            if c and c.get("status") == "OK" and c.get("tput_8", 0) > bv:
                best, bv = eng, c["tput_8"]
        r["winner"] = best
        if best:
            wins[best] += 1
    return wins


def md_report(results, meta, skipped):
    wins = winners(results)
    total = sum(wins.values())
    L = []
    L.append("# Бенчмарк протоколов")
    L.append("")
    L.append("tachyon-core против sing-box-lx, Xray и Mihomo на одинаковой топологии.")
    L.append("")
    L.append("| | |")
    L.append("|---|---|")
    L.append("| Профиль | %d ядер, прокси получает %d |"
             % (meta["cores"], meta["router_cores"]))
    L.append("| CPU | %s |" % meta["cpu"])
    L.append("| Потоков | %d |" % meta["streams"])
    L.append("| Длительность | %d с |" % meta["seconds"])
    L.append("| Раундов латенси | %d |" % meta["rounds"])
    L.append("| Прогон | %s |" % meta["date"])
    L.append("")
    L.append("**Как читать:** `1c / 8c` — ГиБ/с на одном и восьми соединениях, "
             "`p50` — медианная латенси в микросекундах, `RSS` — пиковая память "
             "клиента в МиБ. Прочерк — движок этот протокол не умеет.")
    L.append("")
    L.append("| Протокол | tachyon-core | sing-box-lx | Xray | Mihomo | Победитель |")
    L.append("|---|---|---|---|---|---|")
    for r in results:
        cells = []
        for eng in ENGINES:
            c = r.get(eng)
            if not c:
                cells.append("—")
            elif c.get("status") == "OK":
                cells.append("%.2f / %.2f · %dµs · %.0f М"
                             % (c["tput_1"], c["tput_8"], c["p50"], c["rss"]))
            else:
                cells.append("ошибка")
        who = LABELS[r["winner"]] if r.get("winner") else "—"
        L.append("| %s | %s | %s |" % (r["name"], " | ".join(cells), who))
    L.append("")
    L.append("## Итог")
    L.append("")
    for eng in ENGINES:
        L.append("- **%s**: %d из %d" % (LABELS[eng], wins[eng], total))
    if skipped:
        L.append("")
        L.append("## Не попали в таблицу")
        L.append("")
        for cid, why in skipped:
            L.append("- `%s` — %s" % (cid, why))
    L.append("")
    return "\n".join(L)


def html_report(results, meta, skipped):
    wins = winners(results)
    total = sum(wins.values())
    esc = lambda s: (str(s).replace("&", "&amp;").replace("<", "&lt;")
                     .replace(">", "&gt;"))
    H = []
    H.append("""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Бенчмарк протоколов — tachyon-core против sing-box, Xray, Mihomo</title>
<style>
:root{--bg:#0d0f14;--card:#151821;--line:#242938;--ink:#eef1f7;--muted:#98a0b3;
--win:#123021;--wink:#63e08c;--err:#3a1a1e;--errink:#ff9090}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font:14px/1.55 ui-sans-serif,system-ui,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1360px;margin:0 auto;padding:30px 20px 60px}
h1{font-size:25px;margin:0 0 4px}
.sub{color:var(--muted);margin-bottom:22px;max-width:900px}
.cards{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:9px;
padding:9px 15px;min-width:118px}
.card b{display:block;font-size:20px;margin-top:2px}
.card span{color:var(--muted);font-size:11px;text-transform:uppercase;
letter-spacing:.05em}
.legend{color:var(--muted);margin:14px 0 18px;font-size:13px}
table{width:100%;border-collapse:collapse;background:var(--card);
border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{padding:9px 11px;text-align:left;border-bottom:1px solid var(--line);
white-space:nowrap}
th{background:#1b1f2b;font-size:11px;text-transform:uppercase;letter-spacing:.05em;
color:var(--muted)}
tr:last-child td{border-bottom:none}
td.name{white-space:normal}
td.num{font-variant-numeric:tabular-nums}
td.win{background:var(--win);color:var(--wink);font-weight:600}
td.err{background:var(--err);color:var(--errink);font-size:12px}
h2{font-size:17px;margin:30px 0 10px}
.tally{display:flex;gap:10px;flex-wrap:wrap}
.tally div{background:var(--card);border:1px solid var(--line);border-radius:9px;
padding:11px 17px}
.tally b{font-size:22px;display:block}
code{background:#1b1f2b;padding:1px 5px;border-radius:4px;font-size:12px}
.foot{color:var(--muted);margin-top:26px;font-size:13px;max-width:900px}
</style></head><body><div class="wrap">""")
    H.append("<h1>Бенчмарк протоколов</h1>")
    H.append('<div class="sub">tachyon-core против sing-box-lx, Xray и Mihomo. '
             'Одинаковая топология и одинаковый бюджет CPU: прокси под тестом '
             'притворяется роутером, сервер и генератор нагрузки получают '
             'остальные ядра.</div>')
    H.append('<div class="cards">')
    H.append('<div class="card"><span>Ядер в контейнере</span><b>%d</b></div>'
             % meta["cores"])
    H.append('<div class="card"><span>Бюджет прокси</span><b>%d</b></div>'
             % meta["router_cores"])
    H.append('<div class="card"><span>Соединений</span><b>%d</b></div>'
             % meta["streams"])
    H.append('<div class="card"><span>Раундов</span><b>%d</b></div>'
             % meta["rounds"])
    H.append('</div>')
    H.append('<div class="legend">В ячейке: <code>1c / 8c</code> — ГиБ/с на 1 и 8 '
             'соединениях, затем <code>p50</code> латенси и <code>RSS</code> '
             'пиковой памяти клиента. Прочерк — движок протокол не умеет.</div>')
    H.append("<table><thead><tr><th>Протокол</th>")
    for eng in ENGINES:
        H.append("<th>%s</th>" % LABELS[eng])
    H.append("<th>Победитель</th></tr></thead><tbody>")
    for r in results:
        H.append('<tr><td class="name">%s</td>' % esc(r["name"]))
        for eng in ENGINES:
            c = r.get(eng)
            if not c:
                H.append('<td class="num">—</td>')
            elif c.get("status") == "OK":
                cls = ' class="num win"' if r.get("winner") == eng else ' class="num"'
                H.append("<td%s>%.2f / %.2f · %d&mu;s · %.0f&thinsp;М</td>"
                         % (cls, c["tput_1"], c["tput_8"], c["p50"], c["rss"]))
            else:
                H.append('<td class="num err">ошибка</td>')
        H.append("<td>%s</td></tr>"
                 % (LABELS[r["winner"]] if r.get("winner") else "—"))
    H.append("</tbody></table>")
    H.append("<h2>Итог</h2><div class='tally'>")
    for eng in ENGINES:
        H.append("<div><span>%s</span><b>%d из %d</b></div>"
                 % (LABELS[eng], wins[eng], total))
    H.append("</div>")
    if skipped:
        H.append("<h2>Не попали в таблицу</h2><table><tbody>")
        for cid, why in skipped:
            H.append('<tr><td class="name"><code>%s</code></td><td class="name">%s</td></tr>'
                     % (esc(cid), esc(why)))
        H.append("</tbody></table>")
    H.append('<div class="foot">Серверная сторона туннеля для всех кандидатов '
             'одна и та же — tachyon-core: sing-box-lx не умеет слушать '
             'reality, shadowtls, wireguard, masque и mieru вообще. На '
             'измеряемые числа клиента это не влияет: сервер получает вдвое '
             'больше ядер и в бойлер не уходит.</div>')
    H.append("</div></body></html>")
    return "\n".join(H)


# ------------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tachyon", default="/bench/tachyon-core")
    ap.add_argument("--sing-box", default="/bench/sing-box-lx")
    ap.add_argument("--xray", default="/bench/xray-linux")
    ap.add_argument("--mihomo", default="/bench/mihomo-linux")
    ap.add_argument("--server", default="", help="server binary, default tachyon")
    ap.add_argument("--cores", type=int, default=2,
                    help="CPU budget for the proxy under test")
    ap.add_argument("--seconds", type=int, default=1)
    ap.add_argument("--streams", type=int, default=8)
    ap.add_argument("--rounds", type=int, default=400)
    ap.add_argument("--only", default="")
    ap.add_argument("--out", default="/bench/bench.json")
    ap.add_argument("--html", default="/bench/bench.html")
    ap.add_argument("--md", default="/bench/bench.md")
    args = ap.parse_args()

    bins = {"tachyon": args.tachyon, "sing-box": args.sing_box,
            "xray": args.xray, "mihomo": args.mihomo}
    server_bin = args.server or args.tachyon

    cores = os.cpu_count() or 1
    budget = max(1, min(args.cores, max(1, cores // 2)))
    router = set(range(budget))
    rest = set(range(cores)) - router
    server = set(sorted(rest)[:max(1, budget * 2)])
    load = (set(range(cores)) - router - server) or rest or router

    meta = {"cores": cores, "router_cores": budget, "cpu": "unknown",
            "date": time.strftime("%Y-%m-%d %H:%M"), "streams": args.streams,
            "seconds": args.seconds, "rounds": args.rounds,
            "router": sorted(router), "server": sorted(server),
            "load": sorted(load)}
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    meta["cpu"] = line.split(":", 1)[1].strip()
                    break
    except OSError:
        pass

    print("cores=%d  proxy=%s  server=%s  load=%s"
          % (cores, sorted(router), sorted(server), sorted(load)), flush=True)

    import multiprocessing
    sink = multiprocessing.Process(target=run_sink, args=(load,), daemon=True)
    sink.start()
    wait_listen(SINK_PORT)

    d = tempfile.mkdtemp(prefix="certs_")
    certs = make_certs(d)
    todo = build_cases(certs)
    if args.only:
        want = set(args.only.split(","))
        todo = [c for c in todo if c["id"] in want]

    results = []
    skipped = []
    for case in todo:
        print("\n--- %s (%s)" % (case["name"], case["id"]), flush=True)
        srv = None
        want = case.get("server_bin")
        use = bins.get(want, server_bin) if want else server_bin
        try:
            srv, _ = launch_server(use, case, server, len(server))
        except Exception as e:
            reason = str(e)
            print("  сервер не поднялся: %s" % reason, flush=True)
            skipped.append((case["id"], reason))
            results.append({"id": case["id"], "name": case["name"],
                            "group": case["group"], "winner": None})
            continue

        row = {"id": case["id"], "name": case["name"], "group": case["group"]}
        for eng in ENGINES:
            path = bins[eng]
            if not os.path.exists(path):
                row[eng] = {"status": "FAIL", "error": "no binary"}
                print("  %-9s нет бинаря" % eng, flush=True)
                continue
            cli = None
            try:
                cli, _ = launch_client(eng, path, case, router, budget)
                if cli is None:
                    print("  %-9s не умеет этот протокол" % eng, flush=True)
                    continue
                t1 = measure_throughput(1, args.seconds)
                t8 = measure_throughput(args.streams, args.seconds)
                lat = measure_latency(args.rounds)
                row[eng] = {
                    "status": "OK", "tput_1": t1, "tput_8": t8,
                    "p50": lat[len(lat) // 2],
                    "p99": lat[min(len(lat) - 1, int(len(lat) * 0.99))],
                    "rss": round(proc_rss(cli.pid), 1),
                }
                print("  %-9s 1c: %5.2f G  8c: %5.2f G  p50: %6.0f us  "
                      "p99: %6.0f us  RSS: %5.1f M"
                      % (eng, t1, t8, row[eng]["p50"], row[eng]["p99"],
                         row[eng]["rss"]), flush=True)
            except RuntimeError as e:
                # the engine refused to start: it does not speak this protocol
                row[eng] = {"status": "NONE", "error": str(e)}
                print("  %-9s не умеет: %s" % (eng, e), flush=True)
            except Exception as e:
                row[eng] = {"status": "FAIL", "error": repr(e)}
                print("  %-9s FAIL: %s" % (eng, e), flush=True)
            finally:
                if cli is not None:
                    cli.kill()
                    cli.wait(timeout=5)
                time.sleep(0.2)
        results.append(row)
        srv.kill()
        srv.wait(timeout=5)
        time.sleep(0.2)

    with open(args.out, "w") as f:
        json.dump({"meta": meta, "results": results, "skipped": skipped},
                  f, indent=2)
    with open(args.md, "w", encoding="utf-8") as f:
        f.write(md_report(results, meta, skipped))
    with open(args.html, "w", encoding="utf-8") as f:
        f.write(html_report(results, meta, skipped))
    print("\nготово: %s, %s, %s" % (args.out, args.md, args.html))


if __name__ == "__main__":
    main()
