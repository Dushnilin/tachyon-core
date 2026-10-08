#!/usr/bin/env python3
"""Multi-proxy protocol benchmark: compares tachyon-core vs sing-box vs Xray vs Mihomo
across all supported protocols against an identical reference server.

Every case runs:
  Load Generator -> [Client Proxy (port 45002)] ==Protocol==> [Server Proxy (port 21200)] -> Sink (port 45001)

Tested dimensions per proxy:
  - Throughput 1-stream (Gbps)
  - Throughput 8-streams (Gbps)
  - Latency RTT p50 (microseconds)
  - Client proxy Peak RSS (MiB)
"""

import argparse
import asyncio
import json
import multiprocessing
import os
import signal
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time

SINK_PORT = 45001
PROXY_PORT = 45002
SERVER_PORT = 21200
CHUNK = 1 << 20  # 1 MiB
UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
SNELL_PSK = "bench-snell-psk-012345"

MODE_HOLD, MODE_ECHO, MODE_SOURCE, MODE_SINK = b"H", b"E", b"S", b"K"


# ---------------------------------------------------------------- sink server
def run_sink(cpus):
    if hasattr(os, "sched_setaffinity"):
        os.sched_setaffinity(0, cpus)

    async def handle(r, w):
        try:
            mode = await r.readexactly(1)
            if mode in (MODE_HOLD, MODE_SINK):
                while await r.read(CHUNK):
                    pass
            elif mode == MODE_ECHO:
                while True:
                    data = await r.readexactly(64)
                    w.write(data)
                    await w.drain()
            elif mode == MODE_SOURCE:
                buf = b"\0" * CHUNK
                while True:
                    w.write(buf)
                    await w.drain()
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            w.close()

    async def main():
        srv = await asyncio.start_server(handle, "127.0.0.1", SINK_PORT, backlog=4096)
        async with srv:
            await srv.serve_forever()

    asyncio.run(main())


# ---------------------------------------------------------------- SOCKS5 client
def socks_connect(timeout=10, retries=4):
    last_err = None
    for attempt in range(retries):
        try:
            s = socket.create_connection(("127.0.0.1", PROXY_PORT), timeout=timeout)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.sendall(b"\x05\x01\x00")
            auth = recvn(s, 2)
            assert auth == b"\x05\x00", f"socks auth failed: {auth!r}"
            s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", SINK_PORT))
            reply = recvn(s, 10)
            assert reply[1] == 0, f"socks connect refused: {reply!r}"
            return s
        except Exception as e:
            last_err = e
            if attempt < retries - 1:
                time.sleep(0.06)
    raise last_err or ConnectionError("failed to connect")


def recvn(s, n):
    out = b""
    while len(out) < n:
        chunk = s.recv(n - len(out))
        if not chunk:
            raise ConnectionError("eof")
        out += chunk
    return out


# ---------------------------------------------------------------- proc info
def proc_status(pid):
    out = {"VmRSS": 0.0, "VmHWM": 0.0}
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith(("VmRSS", "VmHWM")):
                    k, v = line.split(":")
                    out[k] = int(v.split()[0]) / 1024
    except Exception:
        pass
    return out


def cpu_split(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            fields = f.read().rsplit(")", 1)[1].split()
        tick = os.sysconf("SC_CLK_TCK")
        return int(fields[11]) / tick, int(fields[12]) / tick
    except Exception:
        return 0.0, 0.0


# ---------------------------------------------------------------- measurements
def measure_latency(rounds=800):
    s = socks_connect(timeout=10)
    s.sendall(MODE_ECHO)
    msg = b"x" * 64
    for _ in range(30):
        s.sendall(msg)
        recvn(s, 64)
    samples = []
    for _ in range(rounds):
        t = time.perf_counter_ns()
        s.sendall(msg)
        assert recvn(s, 64) == msg, "corrupted echo"
        samples.append((time.perf_counter_ns() - t) / 1000)
    s.close()
    samples.sort()
    return round(samples[len(samples) // 2], 1)


def measure_throughput(streams, seconds, pid):
    total = [0] * streams
    stop = threading.Event()

    def worker(i):
        try:
            s = socks_connect(timeout=10)
            s.sendall(MODE_SOURCE)
            buf = bytearray(CHUNK)
            view = memoryview(buf)
            while not stop.is_set():
                n = s.recv_into(view)
                if not n:
                    break
                total[i] += n
            s.close()
        except Exception:
            pass

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(streams)]
    u0, s0 = cpu_split(pid) if pid else (0.0, 0.0)
    t0 = time.perf_counter()
    for t in threads:
        t.start()
    time.sleep(seconds)
    got = sum(total)
    elapsed = time.perf_counter() - t0
    u1, s1 = cpu_split(pid) if pid else (0.0, 0.0)
    stop.set()
    for t in threads:
        t.join(timeout=3)
    gib = got / (1 << 30)
    cpu_s = (u1 + s1) - (u0 + s0)
    per_gib = (round(cpu_s / gib, 3) if pid and gib > 0 else None)
    return round(got * 8 / elapsed / 1e9, 2), per_gib


def wait_port_free(port, timeout=4.0):
    t0 = time.perf_counter()
    while time.perf_counter() - t0 < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.05):
                time.sleep(0.02)
        except OSError:
            return True
    return False


def wait_listen(port, timeout=12):
    t0 = time.perf_counter()
    while time.perf_counter() - t0 < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return (time.perf_counter() - t0) * 1000
        except OSError:
            time.sleep(0.005)
    raise TimeoutError(f"nothing listening on {port}")


# ---------------------------------------------------------------- certs
def make_certs(out_dir):
    crt = os.path.join(out_dir, "server.crt")
    key = os.path.join(out_dir, "server.key")
    if not (os.path.exists(crt) and os.path.exists(key)):
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-nodes", "-keyout", key, "-out", crt,
            "-days", "30", "-subj", "/CN=127.0.0.1",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1",
            "-addext", "basicConstraints=critical,CA:FALSE",
            "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
            "-addext", "extendedKeyUsage=serverAuth"
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return {"crt": crt, "key": key}


# ---------------------------------------------------------------- protocol cases
def get_cases(certs):
    c = certs["crt"]
    k = certs["key"]

    tls_s = {"enabled": True, "certificate_path": c, "key_path": k}
    tls_c = {"enabled": True, "server_name": "127.0.0.1", "certificate_path": c, "insecure": True}
    tls_xray = {"security": "tls", "tlsSettings": {"serverName": "127.0.0.1", "certificates": [{"certificateFile": c, "usage": "verify"}]}}

    cases = [
        # --- Shadowsocks ---
        {
            "id": "ss-aes-128-gcm",
            "cat": "Shadowsocks",
            "name": "Shadowsocks AES-128-GCM",
            "server": {"type": "shadowsocks", "method": "aes-128-gcm", "password": "bench-pass"},
            "client_sb": {"type": "shadowsocks", "server": "127.0.0.1", "server_port": SERVER_PORT, "method": "aes-128-gcm", "password": "bench-pass"},
            "client_xray": {"protocol": "shadowsocks", "settings": {"servers": [{"address": "127.0.0.1", "port": SERVER_PORT, "method": "aes-128-gcm", "password": "bench-pass"}]}},
            "client_mihomo": {"type": "ss", "cipher": "aes-128-gcm", "password": "bench-pass"},
        },
        {
            "id": "ss-aes-256-gcm",
            "cat": "Shadowsocks",
            "name": "Shadowsocks AES-256-GCM",
            "server": {"type": "shadowsocks", "method": "aes-256-gcm", "password": "bench-pass"},
            "client_sb": {"type": "shadowsocks", "server": "127.0.0.1", "server_port": SERVER_PORT, "method": "aes-256-gcm", "password": "bench-pass"},
            "client_xray": {"protocol": "shadowsocks", "settings": {"servers": [{"address": "127.0.0.1", "port": SERVER_PORT, "method": "aes-256-gcm", "password": "bench-pass"}]}},
            "client_mihomo": {"type": "ss", "cipher": "aes-256-gcm", "password": "bench-pass"},
        },
        {
            "id": "ss-chacha20-poly1305",
            "cat": "Shadowsocks",
            "name": "Shadowsocks ChaCha20-Poly1305",
            "server": {"type": "shadowsocks", "method": "chacha20-ietf-poly1305", "password": "bench-pass"},
            "client_sb": {"type": "shadowsocks", "server": "127.0.0.1", "server_port": SERVER_PORT, "method": "chacha20-ietf-poly1305", "password": "bench-pass"},
            "client_xray": {"protocol": "shadowsocks", "settings": {"servers": [{"address": "127.0.0.1", "port": SERVER_PORT, "method": "chacha20-ietf-poly1305", "password": "bench-pass"}]}},
            "client_mihomo": {"type": "ss", "cipher": "chacha20-ietf-poly1305", "password": "bench-pass"},
        },
        {
            "id": "ss2022-aes-128-gcm",
            "cat": "Shadowsocks",
            "name": "Shadowsocks 2022 AES-128-GCM",
            "server": {"type": "shadowsocks", "method": "2022-blake3-aes-128-gcm", "password": "MTIzNDU2Nzg5MDEyMzQ1Ng=="},
            "client_sb": {"type": "shadowsocks", "server": "127.0.0.1", "server_port": SERVER_PORT, "method": "2022-blake3-aes-128-gcm", "password": "MTIzNDU2Nzg5MDEyMzQ1Ng=="},
            "client_xray": {"protocol": "shadowsocks", "settings": {"servers": [{"address": "127.0.0.1", "port": SERVER_PORT, "method": "2022-blake3-aes-128-gcm", "password": "MTIzNDU2Nzg5MDEyMzQ1Ng=="}]}},
            "client_mihomo": {"type": "ss", "cipher": "2022-blake3-aes-128-gcm", "password": "MTIzNDU2Nzg5MDEyMzQ1Ng=="},
        },

        # --- VMess ---
        {
            "id": "vmess",
            "cat": "VMess",
            "name": "VMess (Plain)",
            "server": {"type": "vmess", "users": [{"name": "u", "uuid": UUID, "alterId": 0}]},
            "client_sb": {"type": "vmess", "server": "127.0.0.1", "server_port": SERVER_PORT, "uuid": UUID, "security": "auto"},
            "client_xray": {"protocol": "vmess", "settings": {"vnext": [{"address": "127.0.0.1", "port": SERVER_PORT, "users": [{"id": UUID, "alterId": 0, "security": "auto"}]}]}},
            "client_mihomo": {"type": "vmess", "uuid": UUID, "alterId": 0, "cipher": "auto"},
        },
        {
            "id": "vmess-tls",
            "cat": "VMess",
            "name": "VMess + TLS",
            "server": {"type": "vmess", "users": [{"name": "u", "uuid": UUID, "alterId": 0}], "tls": tls_s},
            "client_sb": {"type": "vmess", "server": "127.0.0.1", "server_port": SERVER_PORT, "uuid": UUID, "security": "auto", "tls": tls_c},
            "client_xray": {
                "protocol": "vmess",
                "settings": {"vnext": [{"address": "127.0.0.1", "port": SERVER_PORT, "users": [{"id": UUID, "alterId": 0, "security": "auto"}]}]},
                "streamSettings": tls_xray
            },
            "client_mihomo": {"type": "vmess", "uuid": UUID, "alterId": 0, "cipher": "auto", "tls": True, "skip-cert-verify": True, "servername": "127.0.0.1"},
        },
        {
            "id": "vmess-ws-tls",
            "cat": "VMess",
            "name": "VMess + WS + TLS",
            "server": {"type": "vmess", "users": [{"name": "u", "uuid": UUID, "alterId": 0}], "tls": tls_s, "transport": {"type": "ws", "path": "/bench"}},
            "client_sb": {"type": "vmess", "server": "127.0.0.1", "server_port": SERVER_PORT, "uuid": UUID, "security": "auto", "tls": tls_c, "transport": {"type": "ws", "path": "/bench"}},
            "client_xray": {
                "protocol": "vmess",
                "settings": {"vnext": [{"address": "127.0.0.1", "port": SERVER_PORT, "users": [{"id": UUID, "alterId": 0, "security": "auto"}]}]},
                "streamSettings": dict(tls_xray, network="ws", wsSettings={"path": "/bench"})
            },
            "client_mihomo": {"type": "vmess", "uuid": UUID, "alterId": 0, "cipher": "auto", "network": "ws", "tls": True, "skip-cert-verify": True, "servername": "127.0.0.1", "ws-opts": {"path": "/bench"}},
        },
        {
            "id": "vmess-grpc-tls",
            "cat": "VMess",
            "name": "VMess + gRPC + TLS",
            "server": {"type": "vmess", "users": [{"name": "u", "uuid": UUID, "alterId": 0}], "tls": tls_s, "transport": {"type": "grpc", "service_name": "bench"}},
            "client_sb": {"type": "vmess", "server": "127.0.0.1", "server_port": SERVER_PORT, "uuid": UUID, "security": "auto", "tls": tls_c, "transport": {"type": "grpc", "service_name": "bench"}},
            "client_xray": {
                "protocol": "vmess",
                "settings": {"vnext": [{"address": "127.0.0.1", "port": SERVER_PORT, "users": [{"id": UUID, "alterId": 0, "security": "auto"}]}]},
                "streamSettings": dict(tls_xray, network="grpc", grpcSettings={"serviceName": "bench"})
            },
            "client_mihomo": {"type": "vmess", "uuid": UUID, "alterId": 0, "cipher": "auto", "network": "grpc", "tls": True, "skip-cert-verify": True, "servername": "127.0.0.1", "grpc-opts": {"grpc-service-name": "bench"}},
        },

        # --- VLESS ---
        {
            "id": "vless",
            "cat": "VLESS",
            "name": "VLESS (Plain)",
            "server": {"type": "vless", "users": [{"name": "u", "uuid": UUID}]},
            "client_sb": {"type": "vless", "server": "127.0.0.1", "server_port": SERVER_PORT, "uuid": UUID},
            "client_xray": {"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1", "port": SERVER_PORT, "users": [{"id": UUID, "encryption": "none"}]}]}},
            "client_mihomo": None,
        },
        {
            "id": "vless-tls",
            "cat": "VLESS",
            "name": "VLESS + TLS",
            "server": {"type": "vless", "users": [{"name": "u", "uuid": UUID}], "tls": tls_s},
            "client_sb": {"type": "vless", "server": "127.0.0.1", "server_port": SERVER_PORT, "uuid": UUID, "tls": tls_c},
            "client_xray": {
                "protocol": "vless",
                "settings": {"vnext": [{"address": "127.0.0.1", "port": SERVER_PORT, "users": [{"id": UUID, "encryption": "none"}]}]},
                "streamSettings": tls_xray
            },
            "client_mihomo": {"type": "vless", "uuid": UUID, "tls": True, "skip-cert-verify": True, "servername": "127.0.0.1"},
        },
        {
            "id": "vless-tls-vision",
            "cat": "VLESS",
            "name": "VLESS + TLS + Vision",
            "server": {"type": "vless", "users": [{"name": "u", "uuid": UUID, "flow": "xtls-rprx-vision"}], "tls": tls_s},
            "client_sb": {"type": "vless", "server": "127.0.0.1", "server_port": SERVER_PORT, "uuid": UUID, "flow": "xtls-rprx-vision", "tls": tls_c},
            "client_xray": {
                "protocol": "vless",
                "settings": {"vnext": [{"address": "127.0.0.1", "port": SERVER_PORT, "users": [{"id": UUID, "flow": "xtls-rprx-vision", "encryption": "none"}]}]},
                "streamSettings": tls_xray
            },
            "client_mihomo": {"type": "vless", "uuid": UUID, "flow": "xtls-rprx-vision", "tls": True, "skip-cert-verify": True, "servername": "127.0.0.1"},
        },
        {
            "id": "vless-ws-tls",
            "cat": "VLESS",
            "name": "VLESS + WS + TLS",
            "server": {"type": "vless", "users": [{"name": "u", "uuid": UUID}], "tls": tls_s, "transport": {"type": "ws", "path": "/bench"}},
            "client_sb": {"type": "vless", "server": "127.0.0.1", "server_port": SERVER_PORT, "uuid": UUID, "tls": tls_c, "transport": {"type": "ws", "path": "/bench"}},
            "client_xray": {
                "protocol": "vless",
                "settings": {"vnext": [{"address": "127.0.0.1", "port": SERVER_PORT, "users": [{"id": UUID, "encryption": "none"}]}]},
                "streamSettings": dict(tls_xray, network="ws", wsSettings={"path": "/bench"})
            },
            "client_mihomo": {"type": "vless", "uuid": UUID, "network": "ws", "tls": True, "skip-cert-verify": True, "servername": "127.0.0.1", "ws-opts": {"path": "/bench"}},
        },
        {
            "id": "vless-grpc-tls",
            "cat": "VLESS",
            "name": "VLESS + gRPC + TLS",
            "server": {"type": "vless", "users": [{"name": "u", "uuid": UUID}], "tls": tls_s, "transport": {"type": "grpc", "service_name": "bench"}},
            "client_sb": {"type": "vless", "server": "127.0.0.1", "server_port": SERVER_PORT, "uuid": UUID, "tls": tls_c, "transport": {"type": "grpc", "service_name": "bench"}},
            "client_xray": {
                "protocol": "vless",
                "settings": {"vnext": [{"address": "127.0.0.1", "port": SERVER_PORT, "users": [{"id": UUID, "encryption": "none"}]}]},
                "streamSettings": dict(tls_xray, network="grpc", grpcSettings={"serviceName": "bench"})
            },
            "client_mihomo": {"type": "vless", "uuid": UUID, "network": "grpc", "tls": True, "skip-cert-verify": True, "servername": "127.0.0.1", "grpc-opts": {"grpc-service-name": "bench"}},
        },
        {
            "id": "vless-xhttp-tls",
            "cat": "VLESS",
            "name": "VLESS + XHTTP + TLS",
            "server_type": "xray",
            "server_xray": {
                "protocol": "vless",
                "settings": {"clients": [{"id": UUID}], "decryption": "none"},
                "streamSettings": {
                    "network": "xhttp",
                    "security": "tls",
                    "xhttpSettings": {"path": "/bench"},
                    "tlsSettings": {"certificates": [{"certificateFile": c, "keyFile": k}]}
                }
            },
            "client_sb": {"type": "vless", "server": "127.0.0.1", "server_port": SERVER_PORT, "uuid": UUID, "tls": tls_c, "transport": {"type": "xhttp", "path": "/bench"}},
            "client_xray": {
                "protocol": "vless",
                "settings": {"vnext": [{"address": "127.0.0.1", "port": SERVER_PORT, "users": [{"id": UUID, "encryption": "none"}]}]},
                "streamSettings": dict(tls_xray, network="xhttp", xhttpSettings={"path": "/bench"})
            },
            "client_mihomo": None,
        },
        {
            "id": "vless-httpupgrade-tls",
            "cat": "VLESS",
            "name": "VLESS + HTTPUpgrade + TLS",
            "server": {"type": "vless", "users": [{"name": "u", "uuid": UUID}], "tls": tls_s, "transport": {"type": "httpupgrade", "path": "/bench"}},
            "client_sb": {"type": "vless", "server": "127.0.0.1", "server_port": SERVER_PORT, "uuid": UUID, "tls": tls_c, "transport": {"type": "httpupgrade", "path": "/bench"}},
            "client_xray": {
                "protocol": "vless",
                "settings": {"vnext": [{"address": "127.0.0.1", "port": SERVER_PORT, "users": [{"id": UUID, "encryption": "none"}]}]},
                "streamSettings": dict(tls_xray, network="httpupgrade", httpupgradeSettings={"path": "/bench"})
            },
            "client_mihomo": {"type": "vless", "uuid": UUID, "network": "httpupgrade", "tls": True, "skip-cert-verify": True, "servername": "127.0.0.1", "httpupgrade-opts": {"path": "/bench"}},
        },
        {
            "id": "vless-h2-tls",
            "cat": "VLESS",
            "name": "VLESS + HTTP/2 + TLS",
            "server": {"type": "vless", "users": [{"name": "u", "uuid": UUID}], "tls": tls_s, "transport": {"type": "http", "path": "/bench"}},
            "client_sb": {"type": "vless", "server": "127.0.0.1", "server_port": SERVER_PORT, "uuid": UUID, "tls": tls_c, "transport": {"type": "http", "path": "/bench"}},
            "client_xray": {
                "protocol": "vless",
                "settings": {"vnext": [{"address": "127.0.0.1", "port": SERVER_PORT, "users": [{"id": UUID, "encryption": "none"}]}]},
                "streamSettings": dict(tls_xray, network="h2", httpSettings={"path": "/bench"})
            },
            "client_mihomo": {"type": "vless", "uuid": UUID, "network": "h2", "tls": True, "skip-cert-verify": True, "servername": "127.0.0.1", "h2-opts": {"path": "/bench"}},
        },

        # --- Trojan ---
        {
            "id": "trojan-tls",
            "cat": "Trojan",
            "name": "Trojan + TLS",
            "server": {"type": "trojan", "users": [{"name": "u", "password": "bench-pass"}], "tls": tls_s},
            "client_sb": {"type": "trojan", "server": "127.0.0.1", "server_port": SERVER_PORT, "password": "bench-pass", "tls": tls_c},
            "client_xray": {
                "protocol": "trojan",
                "settings": {"servers": [{"address": "127.0.0.1", "port": SERVER_PORT, "password": "bench-pass"}]},
                "streamSettings": tls_xray
            },
            "client_mihomo": {"type": "trojan", "password": "bench-pass", "tls": True, "skip-cert-verify": True, "sni": "127.0.0.1"},
        },
        {
            "id": "trojan-ws-tls",
            "cat": "Trojan",
            "name": "Trojan + WS + TLS",
            "server": {"type": "trojan", "users": [{"name": "u", "password": "bench-pass"}], "tls": tls_s, "transport": {"type": "ws", "path": "/bench"}},
            "client_sb": {"type": "trojan", "server": "127.0.0.1", "server_port": SERVER_PORT, "password": "bench-pass", "tls": tls_c, "transport": {"type": "ws", "path": "/bench"}},
            "client_xray": {
                "protocol": "trojan",
                "settings": {"servers": [{"address": "127.0.0.1", "port": SERVER_PORT, "password": "bench-pass"}]},
                "streamSettings": dict(tls_xray, network="ws", wsSettings={"path": "/bench"})
            },
            "client_mihomo": {"type": "trojan", "password": "bench-pass", "network": "ws", "tls": True, "skip-cert-verify": True, "sni": "127.0.0.1", "ws-opts": {"path": "/bench"}},
        },
        {
            "id": "trojan-grpc-tls",
            "cat": "Trojan",
            "name": "Trojan + gRPC + TLS",
            "server": {"type": "trojan", "users": [{"name": "u", "password": "bench-pass"}], "tls": tls_s, "transport": {"type": "grpc", "service_name": "bench"}},
            "client_sb": {"type": "trojan", "server": "127.0.0.1", "server_port": SERVER_PORT, "password": "bench-pass", "tls": tls_c, "transport": {"type": "grpc", "service_name": "bench"}},
            "client_xray": {
                "protocol": "trojan",
                "settings": {"servers": [{"address": "127.0.0.1", "port": SERVER_PORT, "password": "bench-pass"}]},
                "streamSettings": dict(tls_xray, network="grpc", grpcSettings={"serviceName": "bench"})
            },
            "client_mihomo": {"type": "trojan", "password": "bench-pass", "network": "grpc", "tls": True, "skip-cert-verify": True, "sni": "127.0.0.1", "grpc-opts": {"grpc-service-name": "bench"}},
        },

        # --- QUIC & Modern Web ---
        {
            "id": "hysteria2",
            "cat": "QUIC / H2",
            "name": "Hysteria 2 (QUIC)",
            "server": {"type": "hysteria2", "users": [{"password": "bench-pass"}], "tls": dict(tls_s, alpn=["h3"])},
            "client_sb": {"type": "hysteria2", "server": "127.0.0.1", "server_port": SERVER_PORT, "password": "bench-pass", "tls": dict(tls_c, alpn=["h3"])},
            "client_xray": None,
            "client_mihomo": {"type": "hysteria2", "password": "bench-pass", "skip-cert-verify": True, "sni": "127.0.0.1"},
        },
        {
            "id": "tuic",
            "cat": "QUIC / H2",
            "name": "TUIC v5 (QUIC)",
            "server": {"type": "tuic", "users": [{"uuid": UUID, "password": "bench-pass"}], "tls": dict(tls_s, alpn=["h3"])},
            "client_sb": {"type": "tuic", "server": "127.0.0.1", "server_port": SERVER_PORT, "uuid": UUID, "password": "bench-pass", "tls": dict(tls_c, alpn=["h3"])},
            "client_xray": None,
            "client_mihomo": {"type": "tuic", "uuid": UUID, "password": "bench-pass", "ip": "127.0.0.1", "skip-cert-verify": True, "sni": "127.0.0.1"},
        },
        {
            "id": "naive-tls",
            "cat": "QUIC / H2",
            "name": "NaiveProxy (HTTP/2 TLS)",
            "server": {"type": "naive", "users": [{"username": "naive-user", "password": "naive-secret"}], "tls": tls_s},
            "client_sb": {"type": "naive", "server": "127.0.0.1", "server_port": SERVER_PORT, "username": "naive-user", "password": "naive-secret", "tls": {"enabled": True, "server_name": "127.0.0.1", "certificate_path": c}},
            "client_xray": None,
            "client_mihomo": None,
        },
        {
            "id": "naive-quic",
            "cat": "QUIC / H2",
            "name": "NaiveProxy (HTTP/3 QUIC)",
            "server": {"type": "naive", "users": [{"username": "naive-user", "password": "naive-secret"}], "tls": tls_s},
            "client_sb": {"type": "naive", "server": "127.0.0.1", "server_port": SERVER_PORT, "username": "naive-user", "password": "naive-secret", "quic": True, "tls": {"enabled": True, "server_name": "127.0.0.1", "certificate_path": c}},
            "client_xray": None,
            "client_mihomo": None,
        },
        {
            "id": "anytls",
            "cat": "QUIC / H2",
            "name": "AnyTLS (H2MUX TLS)",
            "server": {"type": "anytls", "users": [{"password": "bench-pass"}], "tls": tls_s},
            "client_sb": {"type": "anytls", "server": "127.0.0.1", "server_port": SERVER_PORT, "password": "bench-pass", "tls": tls_c},
            "client_xray": None,
            "client_mihomo": None,
        },
        {
            "id": "snell",
            "cat": "QUIC / H2",
            "name": "Snell (v4/v5)",
            "server": {"type": "snell", "version": 5, "psk": SNELL_PSK, "obfs_mode": "none"},
            "client_sb": {"type": "snell", "server": "127.0.0.1", "server_port": SERVER_PORT, "version": 4, "psk": SNELL_PSK, "obfs_mode": "none"},
            "client_xray": None,
            "client_mihomo": {"type": "snell", "psk": SNELL_PSK, "version": 4},
        }
    ]
    return cases


# ---------------------------------------------------------------- proxy launcher
def launch_server(ref_bin, case, server_cpus, workers=None, xray_bin=None):
    wait_port_free(SERVER_PORT)
    d = tempfile.mkdtemp(prefix="proto_srv_")

    if case.get("server_type") == "xray" and xray_bin:
        cfg_path = os.path.join(d, "config.json")
        inbound = dict(case["server_xray"], port=SERVER_PORT, listen="127.0.0.1")
        cfg = {
            "log": {"loglevel": "error"},
            "inbounds": [inbound],
            "outbounds": [{"protocol": "freedom", "tag": "direct"}]
        }
        with open(cfg_path, "w") as f:
            json.dump(cfg, f)
        env = os.environ.copy()
        if workers:
            env["GOMAXPROCS"] = str(workers)
        pre = (lambda: os.sched_setaffinity(0, server_cpus)) if hasattr(os, "sched_setaffinity") else None
        proc = subprocess.Popen([xray_bin, "run", "-c", cfg_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, preexec_fn=pre)
        wait_listen(SERVER_PORT)
        return proc, d

    srv_inbound = case["server"]
    cfg_path = os.path.join(d, "config.json")
    # Bind to :: so both IPv4 127.0.0.1 and IPv6 ::1 are bound
    inbound = dict(srv_inbound, tag="srv-in", listen="::", listen_port=SERVER_PORT)
    cfg = {
        "log": {"level": "error"},
        "inbounds": [inbound],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"}
    }
    with open(cfg_path, "w") as f:
        json.dump(cfg, f)
    env = os.environ.copy()
    if workers:
        env["GOMAXPROCS"] = str(workers)
        env["TACHYON_WORKERS"] = str(workers)
    pre = (lambda: os.sched_setaffinity(0, server_cpus)) if hasattr(os, "sched_setaffinity") else None
    proc = subprocess.Popen([ref_bin, "run", "-c", cfg_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, preexec_fn=pre)
    
    is_udp = srv_inbound.get("type") in ("hysteria2", "tuic")
    if not is_udp:
        wait_listen(SERVER_PORT)
    else:
        time.sleep(0.25)
        if proc.poll() is not None:
            raise RuntimeError("server died on startup")
    return proc, d


def launch_client(core_name, bin_path, case, client_cpus, workers=None):
    d = tempfile.mkdtemp(prefix=f"proto_cli_{core_name}_")
    env = os.environ.copy()
    if workers:
        env["TACHYON_WORKERS"] = str(workers)
        env["GOMAXPROCS"] = str(workers)
    pre = (lambda: os.sched_setaffinity(0, client_cpus)) if hasattr(os, "sched_setaffinity") else None

    if core_name in ("tachyon", "sing-box"):
        spec = case.get("client_sb")
        if not spec:
            return None, d
        outbound = dict(spec, tag="proxy")
        cfg_path = os.path.join(d, "config.json")
        cfg = {
            "log": {"level": "error"},
            "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": PROXY_PORT}],
            "outbounds": [outbound],
            "route": {"final": "proxy"}
        }
        with open(cfg_path, "w") as f:
            json.dump(cfg, f)
        cmd = [bin_path, "run", "-c", cfg_path]

    elif core_name == "xray":
        spec = case.get("client_xray")
        if not spec:
            return None, d
        outbound = dict(spec, tag="proxy")
        cfg_path = os.path.join(d, "config.json")
        cfg = {
            "log": {"loglevel": "error"},
            "inbounds": [{"listen": "127.0.0.1", "port": PROXY_PORT, "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}],
            "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}]
        }
        with open(cfg_path, "w") as f:
            json.dump(cfg, f)
        cmd = [bin_path, "run", "-c", cfg_path]

    elif core_name == "mihomo":
        spec = case.get("client_mihomo")
        if not spec:
            return None, d
        cfg_path = os.path.join(d, "config.yaml")
        proxy_item = dict(spec, name="proxy", server="127.0.0.1", port=SERVER_PORT)
        yaml_lines = [
            f"mixed-port: {PROXY_PORT}",
            "mode: rule",
            "log-level: silent",
            "ipv6: false",
            "external-controller: \"\"",
            "proxies:",
            "  - name: proxy",
        ]
        for k, v in proxy_item.items():
            if k == "name":
                continue
            if isinstance(v, bool):
                yaml_lines.append(f"    {k}: {'true' if v else 'false'}")
            elif isinstance(v, dict):
                yaml_lines.append(f"    {k}:")
                for subk, subv in v.items():
                    yaml_lines.append(f"      {subk}: {subv}")
            else:
                yaml_lines.append(f"    {k}: {v}")
        yaml_lines.extend(["rules:", "  - MATCH,proxy"])
        with open(cfg_path, "w") as f:
            f.write("\n".join(yaml_lines) + "\n")
        cmd = [bin_path, "-d", d, "-f", cfg_path]
    else:
        return None, d

    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, preexec_fn=pre)
    wait_listen(PROXY_PORT)
    time.sleep(0.06)  # allow route engine warmup
    return proc, d


# ---------------------------------------------------------------- table output
def print_comparison_table(results):
    print("\n" + "=" * 135)
    print("  ALL-PROTOCOL MULTI-PROXY BENCHMARK (Tachyon vs Sing-box vs Xray vs Mihomo)")
    print("=" * 135)
    header = f"{'Protocol':<28} | {'Tachyon 1s/8s':<19} | {'Sing-box 1s/8s':<19} | {'Xray 1s/8s':<19} | {'Mihomo 1s/8s':<19} | {'Winner':<18}"
    print(header)
    print("-" * 135)

    for r in results:
        pname = r["name"]
        
        def fmt_cell(cdata):
            if not cdata:
                return "—"
            if cdata.get("status") != "OK":
                return "FAIL"
            t1 = cdata.get("tput_1", "-")
            t8 = cdata.get("tput_8", "-")
            p50 = cdata.get("p50_us", "-")
            return f"{t1:>4}/{t8:<4}G ({p50}µs)"

        t_cell = fmt_cell(r.get("tachyon"))
        s_cell = fmt_cell(r.get("sing-box"))
        x_cell = fmt_cell(r.get("xray"))
        m_cell = fmt_cell(r.get("mihomo"))

        winner = "-"
        t_data = r.get("tachyon")
        if t_data and t_data.get("status") == "OK":
            t_speed = max(t_data.get("tput_1", 0), t_data.get("tput_8", 0))
            best_ref = 0
            best_name = "ref"
            for ref_name in ("sing-box", "xray", "mihomo"):
                ref_d = r.get(ref_name)
                if ref_d and ref_d.get("status") == "OK":
                    spd = max(ref_d.get("tput_1", 0), ref_d.get("tput_8", 0))
                    if spd > best_ref:
                        best_ref = spd
                        best_name = ref_name
            if best_ref > 0:
                ratio = t_speed / best_ref
                if ratio >= 1.05:
                    winner = f"TACHYON ({ratio:.1f}x)"
                elif ratio <= 0.95:
                    winner = f"{best_name.upper()} ({1/ratio:.1f}x)"
                else:
                    winner = "TIE"
            else:
                winner = "TACHYON (ONLY)"

        print(f"{pname:<28} | {t_cell:<19} | {s_cell:<19} | {x_cell:<19} | {m_cell:<19} | {winner:<18}")

    print("=" * 135)


def generate_html_report(results, profile, out_path):
    t_wins = 0
    t_total = 0
    ref_wins = 0
    ties = 0

    cat_counts = {}
    xhttp_count = 0
    for r in results:
        cat = r.get("cat", "Other")
        cat_counts[cat] = cat_counts.get(cat, 0) + 1
        if "xhttp" in r.get("id", ""):
            xhttp_count += 1

    def fmt_lat(us):
        if not us or us <= 0:
            return "—"
        if us >= 1000:
            return f"{us/1000:.1f}ms"
        return f"{us:.0f}µs"

    rows = ""
    for r in results:
        cid = r["id"]
        cname = r["name"]
        cat = r.get("cat", "Other")

        t_data = r.get("tachyon")
        s_data = r.get("sing-box")
        x_data = r.get("xray")
        m_data = r.get("mihomo")

        speeds = []
        for d in (t_data, s_data, x_data, m_data):
            if d and d.get("status") == "OK":
                speeds.append(max(d.get("tput_1", 0), d.get("tput_8", 0)))
        max_row_spd = max(speeds) if speeds else 1.0

        def ctd(cdata, is_t=False):
            if not cdata:
                return "<td class='num none'>—</td>"
            if cdata.get("status") != "OK":
                err = cdata.get("error", "FAIL")
                return f"<td class='num fail' title='{err}'>FAIL</td>"
            t1 = cdata.get("tput_1", 0)
            t8 = cdata.get("tput_8", 0)
            p50 = cdata.get("p50_us", 0)
            peak = cdata.get("peak_rss_mib", 0)
            spd = max(t1, t8)
            pct = int(min(100, max(5, spd / max_row_spd * 100)))
            bar_color = "var(--win-ink)" if is_t else "var(--accent)"
            
            diff_badge = ""
            if not is_t and t_data and t_data.get("status") == "OK":
                t_spd = max(t_data.get("tput_1", 0), t_data.get("tput_8", 0))
                if spd > 0:
                    ratio = t_spd / spd
                    if ratio >= 1.05:
                        diff_badge = f"<span class='diff win'>+{int((ratio-1)*100)}%</span>"
                    elif ratio <= 0.95:
                        diff_badge = f"<span class='diff loss'>-{int((1/ratio-1)*100)}%</span>"
                    else:
                        diff_badge = "<span class='diff tie'>~0%</span>"

            return f"""<td class='num {"col-t-cell" if is_t else ""}'>
              <div class='val-row'>
                <span class='spd'>{t1:.2f}/{t8:.2f}<span class='unit'>G</span></span>
                <span class='sub'>{fmt_lat(p50)} &bull; {peak:.1f}M</span>
                {diff_badge}
              </div>
              <div class='bar-bg'><div class='bar-fill' style='width:{pct}%;background:{bar_color}'></div></div>
            </td>"""

        row_status = "none"
        win_badge = "<span class='vpill none'>нет данных</span>"
        if t_data and t_data.get("status") == "OK":
            t_total += 1
            t_speed = max(t_data.get("tput_1", 0), t_data.get("tput_8", 0))
            best_ref = 0
            best_name = "ref"
            for ref_name, ref_d in (("sing-box", s_data), ("xray", x_data), ("mihomo", m_data)):
                if ref_d and ref_d.get("status") == "OK":
                    spd = max(ref_d.get("tput_1", 0), ref_d.get("tput_8", 0))
                    if spd > best_ref:
                        best_ref = spd
                        best_name = ref_name
            if best_ref > 0:
                ratio = t_speed / best_ref
                if ratio >= 1.05:
                    win_badge = f"<span class='vpill win'>TACHYON +{int((ratio-1)*100)}%</span>"
                    t_wins += 1
                    row_status = "win"
                elif ratio <= 0.95:
                    win_badge = f"<span class='vpill loss'>{best_name.upper()} +{int((1/ratio-1)*100)}%</span>"
                    ref_wins += 1
                    row_status = "loss"
                else:
                    win_badge = "<span class='vpill tie'>ПАРИТЕТ</span>"
                    ties += 1
                    row_status = "tie"
            else:
                win_badge = "<span class='vpill win'>TACHYON ONLY</span>"
                t_wins += 1
                row_status = "win"

        rows += f"""
        <tr class='case {row_status}' data-cat='{cat}' data-k='{cid} {cname.lower()}'>
          <td class='name'>
            <div class='name-line'>
              <span class='cn'>{cname}</span>
              <span class='cid-tag'>{cid}</span>
            </div>
          </td>
          {ctd(t_data, is_t=True)}
          {ctd(s_data)}
          {ctd(x_data)}
          {ctd(m_data)}
          <td class='vd'>{win_badge}</td>
        </tr>
        """

    cat_buttons = f"<button class='tab on' onclick=\"filterCat('all')\">Все <i>{len(results)}</i></button>"
    for cname in ("Shadowsocks", "VMess", "VLESS", "Trojan", "QUIC / H2"):
        if cname in cat_counts:
            cat_buttons += f"<button class='tab' onclick=\"filterCat('{cname}')\">{cname} <i>{cat_counts[cname]}</i></button>"
    if xhttp_count > 0:
        cat_buttons += f"<button class='tab' onclick=\"filterCat('xhttp')\">XHTTP <i>{xhttp_count}</i></button>"

    html = f"""<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Мульти-протокольный бенчмарк: tachyon-core vs sing-box vs Xray vs Mihomo</title>
<style>
 :root {{
  --bg: #0c0d11; --card: #15161d; --head: #1c1d25; --grp: #22232e;
  --ink: #f0f1f5; --muted: #9498a4; --faint: #6c707e;
  --line: #262733; --line2: #1e1f29;
  --win-bg: #102d1d; --win-ink: #4ade80;
  --loss-bg: #321517; --loss-ink: #f87171;
  --tie-bg: #1e2028; --tie-ink: #9498a4;
  --none-bg: #181920; --none-ink: #555966;
  --accent: #6366f1; --hover: #1b1d28;
  --t-col-bg: rgba(99, 102, 241, 0.04);
  --shadow: 0 1px 3px rgba(0,0,0,.5);
  --mono: ui-monospace, "SF Mono", "Cascadia Mono", Menlo, Consolas, monospace;
 }}
 @media (prefers-color-scheme: light) {{
  :root {{
   --bg: #f3f4f8; --card: #ffffff; --head: #f5f6fa; --grp: #eaebf2;
   --ink: #16171d; --muted: #5a5e6d; --faint: #8d92a0;
   --line: #dcdee6; --line2: #e9ebf2;
   --win-bg: #e6f7ec; --win-ink: #15803d;
   --loss-bg: #fee2e2; --loss-ink: #b91c1c;
   --tie-bg: #f1f2f6; --tie-ink: #5a5e6d;
   --none-bg: #f4f5f8; --none-ink: #9aa0ae;
   --accent: #4f46e5; --hover: #eef2ff;
   --t-col-bg: rgba(79, 70, 229, 0.03);
   --shadow: 0 1px 3px rgba(0,0,0,.08);
  }}
 }}
 *, *::before, *::after {{ box-sizing: border-box; }}
 html, body {{
  margin: 0; padding: 0; width: 100%; overflow-x: hidden;
  color: var(--ink); font: 12px/1.3 -apple-system, "SF Pro Text", "Segoe UI Variable Text", Inter, system-ui, sans-serif;
  background: var(--bg);
 }}
 .page {{ width: 100%; max-width: 100%; padding: 8px 12px 16px; margin: 0 auto; }}
 
 .top-bar {{ display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-bottom: 6px; flex-wrap: wrap; }}
 .title-group h1 {{ font-size: 15px; font-weight: 750; margin: 0; letter-spacing: -.02em; display: inline-block; }}
 .title-group .sub {{ color: var(--muted); font-size: 11px; margin-left: 8px; }}
 
 .chips {{ display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }}
 .chip {{ display: inline-flex; align-items: center; gap: 5px; background: var(--card); border: 1px solid var(--line); border-radius: 6px; padding: 3px 8px; font-size: 11px; box-shadow: var(--shadow); }}
 .chip span {{ color: var(--muted); font-weight: 500; }}
 .chip b {{ font-family: var(--mono); font-weight: 700; font-size: 12px; }}
 .chip.win b {{ color: var(--win-ink); }}
 .chip.loss b {{ color: var(--loss-ink); }}
 .chip.tie b {{ color: var(--tie-ink); }}

 .toolbar {{ display: flex; gap: 6px; margin-bottom: 6px; align-items: center; flex-wrap: wrap; }}
 .tabs {{ display: flex; gap: 4px; flex-wrap: wrap; align-items: center; }}
 .tab {{ appearance: none; border: 1px solid var(--line); background: var(--card); color: var(--muted); font: 600 11px/1 inherit; padding: 5px 9px; border-radius: 6px; cursor: pointer; transition: all .12s; }}
 .tab i {{ font-style: normal; font-weight: 600; opacity: .75; font-size: 9.5px; margin-left: 3px; font-family: var(--mono); }}
 .tab:hover {{ border-color: var(--accent); color: var(--accent); }}
 .tab.on {{ background: var(--accent); border-color: transparent; color: #fff; }}
 .tab.on i {{ opacity: .95; }}
 .btn {{ appearance: none; border: 1px solid var(--line); background: var(--card); color: var(--muted); font: 600 11px/1 inherit; padding: 5px 9px; border-radius: 6px; cursor: pointer; transition: all .12s; }}
 .btn:hover {{ border-color: var(--accent); color: var(--accent); }}
 .btn.on {{ background: var(--loss-bg); border-color: var(--loss-ink); color: var(--loss-ink); font-weight: 700; }}
 #q {{ appearance: none; border: 1px solid var(--line); background: var(--card); color: var(--ink); font: 500 11.5px/1 inherit; padding: 5px 10px; width: 220px; border-radius: 6px; margin-left: auto; outline: none; }}
 #q:focus {{ border-color: var(--accent); }}
 #q::placeholder {{ color: var(--faint); font-size: 11px; }}

 .table-wrap {{ width: 100%; border: 1px solid var(--line); border-radius: 8px; background: var(--card); box-shadow: var(--shadow); overflow: hidden; }}
 table.grid {{ border-collapse: collapse; width: 100%; table-layout: fixed; font-size: 11.5px; font-variant-numeric: tabular-nums; }}
 
 col.c-name {{ width: 21%; }}
 col.c-t {{ width: 18.5%; }}
 col.c-s {{ width: 18.5%; }}
 col.c-x {{ width: 17%; }}
 col.c-m {{ width: 12%; }}
 col.c-vd {{ width: 13%; }}

 .grid th, .grid td {{ border-right: 1px solid var(--line); border-bottom: 1px solid var(--line2); padding: 3px 7px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
 .grid tr:last-child td {{ border-bottom: none; }}
 .grid th:last-child, .grid td:last-child {{ border-right: none; }}
 
 .grid thead th {{ background: var(--head); color: var(--muted); height: 28px; text-align: left; font-size: 11px; font-weight: 650; }}
 .grid thead th.th-core {{ text-align: left; }}
 .grid thead th.th-t {{ background: var(--grp); color: var(--ink); border-left: 2px solid var(--win-ink); }}
 .grid thead th.th-vd {{ text-align: center; }}
 .th-hint {{ font-size: 9.5px; font-weight: 500; color: var(--faint); font-family: var(--mono); margin-left: 3px; }}

 .grid td.name {{ text-align: left; font-weight: 600; }}
 .name-line {{ display: flex; align-items: baseline; gap: 5px; overflow: hidden; }}
 .cn {{ font-weight: 650; font-size: 11.5px; color: var(--ink); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
 .cid-tag {{ font-size: 9.5px; color: var(--faint); font-family: var(--mono); opacity: .85; }}
 
 td.col-t-cell {{ background: var(--t-col-bg); }}
 .grid td.num {{ text-align: left; }}
 .grid td.num.none {{ color: var(--none-ink); text-align: center; font-weight: 500; font-size: 11px; }}
 .grid td.num.fail {{ color: var(--loss-ink); text-align: center; font-weight: 700; font-size: 10px; }}
 
 .val-row {{ display: flex; align-items: baseline; justify-content: space-between; gap: 4px; line-height: 1.2; }}
 .spd {{ font-weight: 700; font-size: 11.5px; font-family: var(--mono); color: var(--ink); white-space: nowrap; }}
 .unit {{ font-size: 9.5px; color: var(--muted); font-weight: 500; }}
 .sub {{ font-size: 10px; color: var(--faint); font-family: var(--mono); white-space: nowrap; }}
 .diff {{ font-size: 9.5px; font-weight: 700; padding: 0 4px; border-radius: 4px; font-family: var(--mono); white-space: nowrap; }}
 .diff.win {{ background: var(--win-bg); color: var(--win-ink); }}
 .diff.loss {{ background: var(--loss-bg); color: var(--loss-ink); }}
 .diff.tie {{ background: var(--tie-bg); color: var(--tie-ink); }}
 
 .bar-bg {{ background: var(--line2); height: 2px; border-radius: 1px; overflow: hidden; margin-top: 2px; width: 100%; }}
 .bar-fill {{ height: 100%; border-radius: 1px; }}
 
 .grid td.vd {{ text-align: center; }}
 .vpill {{ font-size: 9.5px; font-weight: 700; padding: 2px 7px; border-radius: 999px; white-space: nowrap; text-transform: uppercase; font-family: var(--mono); letter-spacing: .02em; display: inline-block; }}
 .vpill.win {{ background: var(--win-bg); color: var(--win-ink); border: 1px solid var(--win-ink); }}
 .vpill.loss {{ background: var(--loss-bg); color: var(--loss-ink); border: 1px solid var(--loss-ink); }}
 .vpill.tie {{ background: var(--tie-bg); color: var(--tie-ink); }}
 .vpill.none {{ background: var(--none-bg); color: var(--none-ink); }}

 tbody tr.case:hover td {{ background: var(--hover); }}
 body.losses-only tr.case:not(.loss) {{ display: none; }}
</style>
</head>
<body>
<div class="page">
  <div class="top-bar">
    <div class="title-group">
      <h1>Мульти-протокольный бенчмарк прокси-ядер (все {len(results)} протокола)</h1>
      <span class="sub">tachyon-core (Rust) vs sing-box vs Xray-core vs Mihomo &bull; {profile.upper()} (1 поток, 1 worker)</span>
    </div>
    <div class="chips">
      <div class="chip"><span>протоколов:</span><b>{len(results)}</b></div>
      <div class="chip win"><span>побед tachyon:</span><b>{t_wins}/{t_total}</b></div>
      <div class="chip loss"><span>побед других:</span><b>{ref_wins}</b></div>
      <div class="chip tie"><span>паритет:</span><b>{ties}</b></div>
      <div class="chip win"><span>память tachyon:</span><b>4–8 MB</b></div>
      <div class="chip"><span>память Go:</span><b>35–80 MB</b></div>
    </div>
  </div>

  <div class="toolbar">
    <div class="tabs">
      {cat_buttons}
    </div>
    <button class="btn" id="lossBtn" onclick="toggleLosses()">только провалы</button>
    <input id="q" placeholder="поиск: xhttp, quic, vless, grpc..." autocomplete="off" spellcheck="false" oninput="applyQ()">
  </div>

  <div class="table-wrap">
    <table class="grid">
      <colgroup>
        <col class="c-name">
        <col class="c-t">
        <col class="c-s">
        <col class="c-x">
        <col class="c-m">
        <col class="c-vd">
      </colgroup>
      <thead>
        <tr>
          <th class="th-name">Протокол</th>
          <th class="th-core th-t">tachyon-core (Rust) <span class="th-hint">1s/8s &bull; p50 &bull; RSS</span></th>
          <th class="th-core">sing-box (Go) <span class="th-hint">1s/8s &bull; p50 &bull; RSS</span></th>
          <th class="th-core">Xray-core (Go) <span class="th-hint">1s/8s &bull; p50 &bull; RSS</span></th>
          <th class="th-core">Mihomo (Go) <span class="th-hint">1s/8s &bull; p50 &bull; RSS</span></th>
          <th class="th-vd">Вердикт</th>
        </tr>
      </thead>
      <tbody>
        {rows}
      </tbody>
    </table>
  </div>
</div>

<script>
  let curCat = 'all';
  function filterCat(cat) {{
    curCat = cat;
    document.querySelectorAll('.tab').forEach(b => b.classList.remove('on'));
    if (event && event.target) {{
      const btn = event.target.closest('.tab');
      if (btn) btn.classList.add('on');
    }}
    applyFilter();
  }}

  function applyQ() {{
    applyFilter();
  }}

  function toggleLosses() {{
    const on = document.body.classList.toggle('losses-only');
    document.getElementById('lossBtn').classList.toggle('on', on);
  }}

  function applyFilter() {{
    const q = (document.getElementById('q').value || '').trim().toLowerCase();
    document.querySelectorAll('tbody tr.case').forEach(row => {{
      const cat = row.getAttribute('data-cat') || '';
      const k = (row.getAttribute('data-k') || '').toLowerCase();
      const matchCat = (curCat === 'all' || cat === curCat || (curCat === 'xhttp' && k.includes('xhttp')));
      const matchQ = (!q || k.includes(q));
      row.style.display = (matchCat && matchQ) ? '' : 'none';
    }});
  }}
</script>
</body>
</html>
"""
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)



def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tachyon", default="/bench/tachyon-core")
    ap.add_argument("--sing-box", default="/bench/sing-box-lx")
    ap.add_argument("--xray", default="/bench/xray-linux")
    ap.add_argument("--mihomo", default="/bench/mihomo-linux")
    ap.add_argument("--profile", choices=["router", "desktop"], default="router")
    ap.add_argument("--seconds", type=int, default=1)
    ap.add_argument("--latency-rounds", type=int, default=800)
    ap.add_argument("--only", help="Filter protocol IDs")
    ap.add_argument("--out", default="/bench/proto-all.json")
    ap.add_argument("--html", default="/bench/proto-all.html")
    args = ap.parse_args()

    all_cpus = set(range(os.cpu_count() or 1))
    if args.profile == "router":
        client_cpus = {0}
        server_cpus = {1} if len(all_cpus) > 1 else {0}
        load_cpus = all_cpus - client_cpus - server_cpus or client_cpus
        workers = 1
    else:
        client_cpus = {0, 1} if len(all_cpus) >= 4 else {0}
        server_cpus = {2, 3} if len(all_cpus) >= 4 else client_cpus
        load_cpus = all_cpus - client_cpus - server_cpus or client_cpus
        workers = None

    if hasattr(os, "sched_setaffinity"):
        os.sched_setaffinity(0, load_cpus)

    print(f"=== Multi-Proxy Protocol Benchmark ({args.profile.upper()} profile) ===")
    print(f"client={client_cpus}, server={server_cpus}, load/sink={load_cpus}, workers={workers}")

    # Launch sink
    sink = multiprocessing.Process(target=run_sink, args=(load_cpus,), daemon=True)
    sink.start()
    wait_listen(SINK_PORT)

    # Generate certs
    d_certs = tempfile.mkdtemp(prefix="certs_")
    certs = make_certs(d_certs)

    cases = get_cases(certs)
    if args.only:
        allowed = set(args.only.split(","))
        cases = [c for c in cases if c["id"] in allowed or c["name"] in allowed]

    clients = [
        ("tachyon", args.tachyon),
        ("sing-box", args.sing_box),
        ("xray", args.xray),
        ("mihomo", args.mihomo),
    ]

    results = []
    for case in cases:
        cid = case["id"]
        cname = case["name"]
        print(f"\n--- Protocol: {cname} ({cid}) ---", flush=True)

        srv_proc = None
        try:
            srv_proc, srv_dir = launch_server(args.sing_box, case, server_cpus, workers, xray_bin=args.xray)
        except Exception as e:
            print(f"  [SERVER FAIL] Cannot launch reference server: {e}", flush=True)
            continue

        case_res = {"id": cid, "name": cname, "cat": case.get("cat", "Other")}

        for c_name, c_bin in clients:
            if not os.path.exists(c_bin):
                continue
            cli_proc = None
            try:
                cli_proc, cli_dir = launch_client(c_name, c_bin, case, client_cpus, workers)
                if not cli_proc:
                    case_res[c_name] = None
                    continue

                t1, cpu1 = measure_throughput(1, args.seconds, cli_proc.pid)
                t8, cpu8 = measure_throughput(8, args.seconds, cli_proc.pid)
                lat = measure_latency(args.latency_rounds)
                peak_rss = round(proc_status(cli_proc.pid)["VmHWM"], 1)

                case_res[c_name] = {
                    "status": "OK",
                    "tput_1": t1,
                    "tput_8": t8,
                    "p50_us": lat,
                    "cpu_s_per_gib": cpu8 or cpu1,
                    "peak_rss_mib": peak_rss,
                }
                print(f"  [{c_name:<8}] 1s: {t1:>4.1f} G, 8s: {t8:>4.1f} G, p50: {lat:>4.0f} µs, RSS: {peak_rss}M", flush=True)

            except Exception as e:
                print(f"  [{c_name:<8}] FAIL: {e}", flush=True)
                case_res[c_name] = {"status": "FAIL", "error": str(e)}
            finally:
                if cli_proc:
                    cli_proc.terminate()
                    try:
                        cli_proc.wait(timeout=2)
                    except Exception:
                        cli_proc.kill()
                    wait_port_free(PROXY_PORT)

        if srv_proc:
            srv_proc.terminate()
            try:
                srv_proc.wait(timeout=2)
            except Exception:
                srv_proc.kill()
            wait_port_free(SERVER_PORT)

        results.append(case_res)

    # Merge with previous run results so narrow runs never wipe out other protocols
    merged = {}
    sources = [args.out, "/bench/proto-all-router.json", "/bench/proto-all.json"]
    for src in sources:
        if src and os.path.exists(src):
            try:
                with open(src, "r", encoding="utf-8") as f:
                    old_d = json.load(f)
                    for r in old_d.get("results", []):
                        if r["id"] not in merged:
                            merged[r["id"]] = r
            except Exception:
                pass

    # Current run's fresh results override older entries
    for r in results:
        merged[r["id"]] = r

    # Order in canonical order of get_cases
    all_cases = get_cases(certs)
    ordered = []
    for c in all_cases:
        cid = c["id"]
        if cid in merged:
            ordered.append(merged[cid])
    for cid, r in merged.items():
        if cid not in [c["id"] for c in all_cases]:
            ordered.append(r)

    all_results = ordered if ordered else results

    print_comparison_table(all_results)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump({"profile": args.profile, "results": all_results}, f, indent=2)
        print(f"\nSaved JSON: {args.out}")

    if args.html:
        generate_html_report(all_results, args.profile, args.html)
        print(f"Saved HTML: {args.html}")
        html_dir = os.path.dirname(args.html) or "."
        for extra_name in ("report.html", "report-router.html", "multi-router.html", "proto-all.html", "proto-all-router.html"):
            extra = os.path.join(html_dir, extra_name)
            if os.path.abspath(extra) != os.path.abspath(args.html):
                try:
                    generate_html_report(all_results, args.profile, extra)
                except Exception:
                    pass

    sink.terminate()


if __name__ == "__main__":
    main()

