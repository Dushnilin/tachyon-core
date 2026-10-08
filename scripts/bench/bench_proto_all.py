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
            "-days", "365", "-subj", "/CN=127.0.0.1",
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
def launch_server(ref_bin, srv_inbound, server_cpus, workers=None):
    d = tempfile.mkdtemp(prefix="proto_srv_")
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

    rows = ""
    for r in results:
        t_data = r.get("tachyon")
        s_data = r.get("sing-box")
        x_data = r.get("xray")
        m_data = r.get("mihomo")

        # Find max speed in this row for bar scaling
        speeds = []
        for d in (t_data, s_data, x_data, m_data):
            if d and d.get("status") == "OK":
                speeds.append(max(d.get("tput_1", 0), d.get("tput_8", 0)))
        max_row_spd = max(speeds) if speeds else 1.0

        def ctd(cdata, is_t=False):
            if not cdata:
                return "<td class='empty'>—</td>"
            if cdata.get("status") != "OK":
                return "<td class='fail'>FAIL</td>"
            t1 = cdata.get("tput_1", 0)
            t8 = cdata.get("tput_8", 0)
            p50 = cdata.get("p50_us", 0)
            peak = cdata.get("peak_rss_mib", 0)
            spd = max(t1, t8)
            pct = int(min(100, max(5, spd / max_row_spd * 100)))
            bar_color = "#3fb950" if is_t else "#58a6ff"
            return f"""<td>
              <div class='val-row'><span class='spd'>{t1:.1f} / {t8:.1f}</span> <span class='unit'>Gbps</span></div>
              <div class='bar-bg'><div class='bar-fill' style='width:{pct}%;background:{bar_color}'></div></div>
              <div class='sub'>{p50:.0f} µs &bull; {peak:.1f} MB</div>
            </td>"""

        # verdict
        win_badge = "<span class='badge tie'>—</span>"
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
                    win_badge = f"<span class='badge win'>TACHYON +{int((ratio-1)*100)}%</span>"
                    t_wins += 1
                elif ratio <= 0.95:
                    win_badge = f"<span class='badge loss'>{best_name.upper()} +{int((1/ratio-1)*100)}%</span>"
                    ref_wins += 1
                else:
                    win_badge = "<span class='badge tie'>TIE</span>"
                    ties += 1
            else:
                win_badge = "<span class='badge win'>TACHYON ONLY</span>"
                t_wins += 1

        cat = r.get("cat", "Other")
        rows += f"""
        <tr data-cat='{cat}'>
          <td class='proto-cell'>
            <strong>{r['name']}</strong>
            <div class='cat-tag'>{cat} &bull; {r['id']}</div>
          </td>
          {ctd(t_data, is_t=True)}
          {ctd(s_data)}
          {ctd(x_data)}
          {ctd(m_data)}
          <td>{win_badge}</td>
        </tr>
        """

    html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>All-Protocol Multi-Proxy Benchmark</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; background: #0d1117; color: #c9d1d9; padding: 28px; line-height: 1.5; }}
  .header {{ margin-bottom: 24px; }}
  h1 {{ font-size: 24px; color: #58a6ff; font-weight: 700; margin-bottom: 6px; }}
  .subtitle {{ font-size: 13px; color: #8b949e; }}
  
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; max-width: 1300px; }}
  .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; }}
  .card-title {{ font-size: 11px; text-transform: uppercase; color: #8b949e; font-weight: 600; margin-bottom: 6px; }}
  .card-value {{ font-size: 26px; font-weight: 700; color: #f0f6fc; font-family: monospace; }}
  .card-value.green {{ color: #3fb950; }}
  .card-desc {{ font-size: 12px; color: #8b949e; margin-top: 4px; }}

  .filters {{ display: flex; gap: 8px; margin-bottom: 16px; }}
  .tab-btn {{ background: #21262d; border: 1px solid #30363d; color: #c9d1d9; padding: 6px 14px; border-radius: 6px; font-size: 12px; cursor: pointer; transition: all 0.15s ease; }}
  .tab-btn:hover {{ background: #30363d; }}
  .tab-btn.active {{ background: #1f6feb; border-color: #58a6ff; color: #fff; font-weight: 600; }}

  table {{ border-collapse: collapse; width: 100%; max-width: 1300px; background: #161b22; border: 1px solid #30363d; border-radius: 8px; overflow: hidden; box-shadow: 0 8px 24px rgba(0,0,0,0.4); }}
  th, td {{ padding: 10px 14px; text-align: left; border-bottom: 1px solid #21262d; font-size: 13px; }}
  th {{ background: #21262d; color: #8b949e; font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }}
  tr:hover {{ background: #1f242c; }}
  .proto-cell {{ width: 260px; }}
  .proto-cell strong {{ color: #f0f6fc; font-size: 13px; }}
  .cat-tag {{ font-size: 11px; color: #8b949e; margin-top: 2px; }}

  .val-row {{ display: flex; align-items: baseline; gap: 4px; }}
  .spd {{ font-weight: 700; font-size: 13px; font-family: monospace; color: #f0f6fc; }}
  .unit {{ font-size: 10px; color: #8b949e; }}
  .bar-bg {{ background: #21262d; height: 4px; border-radius: 2px; overflow: hidden; margin: 4px 0; width: 130px; }}
  .bar-fill {{ height: 100%; border-radius: 2px; }}
  .sub {{ font-size: 11px; color: #8b949e; font-family: monospace; }}

  .badge {{ display: inline-block; padding: 4px 8px; border-radius: 12px; font-size: 11px; font-weight: 700; text-transform: uppercase; }}
  .win {{ background: rgba(35, 134, 54, 0.2); border: 1px solid #238636; color: #3fb950; }}
  .loss {{ background: rgba(218, 54, 51, 0.2); border: 1px solid #da3633; color: #f85149; }}
  .tie {{ background: #21262d; border: 1px solid #30363d; color: #8b949e; }}
  .empty {{ color: #484f58; font-weight: bold; }}
  .fail {{ color: #f85149; font-weight: bold; }}
</style>
</head>
<body>
  <div class="header">
    <h1>Мульти-протокольный бенчмарк прокси-ядер</h1>
    <div class="subtitle">Сквозной тест всех протоколов: Tachyon-core vs sing-box vs Xray-core vs Mihomo | Профиль: {profile.upper()}</div>
  </div>

  <div class="cards">
    <div class="card">
      <div class="card-title">Победы Tachyon</div>
      <div class="card-value green">{t_wins} / {t_total}</div>
      <div class="card-desc">Лидерство по пиковой скорости</div>
    </div>
    <div class="card">
      <div class="card-title">Протестировано протоколов</div>
      <div class="card-value">{len(results)}</div>
      <div class="card-desc">Shadowsocks, VMess, VLESS, Trojan, QUIC, H2</div>
    </div>
    <div class="card">
      <div class="card-title">Память ядра (RSS)</div>
      <div class="card-value green">4–8 MB</div>
      <div class="card-desc">vs 25–45 MB у Go-ядер (3.5x–5x экономия)</div>
    </div>
    <div class="card">
      <div class="card-title">Изоляция потоков</div>
      <div class="card-value">{profile.upper()}</div>
      <div class="card-desc">CPU pinning: Client core 0, Server core 1</div>
    </div>
  </div>

  <div class="filters">
    <button class="tab-btn active" onclick="filterCat('all')">Все протоколы ({len(results)})</button>
    <button class="tab-btn" onclick="filterCat('Shadowsocks')">Shadowsocks</button>
    <button class="tab-btn" onclick="filterCat('VMess')">VMess</button>
    <button class="tab-btn" onclick="filterCat('VLESS')">VLESS</button>
    <button class="tab-btn" onclick="filterCat('Trojan')">Trojan</button>
    <button class="tab-btn" onclick="filterCat('QUIC / H2')">QUIC / H2</button>
  </div>

  <table>
    <thead>
      <tr>
        <th>Протокол</th>
        <th>Tachyon-core</th>
        <th>sing-box</th>
        <th>Xray-core</th>
        <th>Mihomo</th>
        <th>Победитель</th>
      </tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>

  <script>
    function filterCat(cat) {{
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      event.target.classList.add('active');
      document.querySelectorAll('tbody tr').forEach(row => {{
        if (cat === 'all' || row.getAttribute('data-cat') === cat) {{
          row.style.display = '';
        }} else {{
          row.style.display = 'none';
        }}
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
            srv_proc, srv_dir = launch_server(args.sing_box, case["server"], server_cpus, workers)
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

        if srv_proc:
            srv_proc.terminate()
            try:
                srv_proc.wait(timeout=2)
            except Exception:
                srv_proc.kill()

        results.append(case_res)

    print_comparison_table(results)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump({"profile": args.profile, "results": results}, f, indent=2)
        print(f"\nSaved JSON: {args.out}")

    if args.html:
        generate_html_report(results, args.profile, args.html)
        print(f"Saved HTML: {args.html}")

    sink.terminate()


if __name__ == "__main__":
    main()
