#!/usr/bin/env python3
"""Benchmark for tachyon-core TUN inbound (Phase F6).

Measures:
  - TCP Throughput (1-stream & 8-stream, Gbit/s)
  - Round-Trip Latency (RTT p50, p95, p99 in microseconds)
  - Process Memory (Peak RSS in MiB)
  - CPU Efficiency (CPU-seconds per GiB transferred)
  - Direct baseline vs TUN comparison
"""

import argparse
import asyncio
import json
import os
import signal
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import time

SINK_PORT = 45000
TUN_IP = "172.19.200.1"
PEER_IP = "172.19.200.2"
TUN_IFNAME = "tun_bench"
CHUNK = 128 * 1024


def run_sink():
    """High-performance asyncio TCP sink and echo server."""
    async def handle_client(reader, writer):
        try:
            cmd = await reader.readexactly(1)
            if cmd == b"E":  # Echo mode (latency)
                while True:
                    data = await reader.read(4096)
                    if not data:
                        break
                    writer.write(data)
                    await writer.drain()
            elif cmd == b"S":  # Sink mode (upload throughput)
                while True:
                    data = await reader.read(CHUNK)
                    if not data:
                        break
            elif cmd == b"D":  # Download mode (download throughput)
                buf = b"X" * CHUNK
                while True:
                    writer.write(buf)
                    await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            writer.close()

    async def main():
        server = await asyncio.start_server(handle_client, "127.0.0.1", SINK_PORT, backlog=1024)
        async with server:
            await server.serve_forever()

    asyncio.run(main())


def get_process_metrics(pid):
    """Read VmHWM / VmRSS and CPU time (utime + stime) from /proc."""
    rss_mib = 0.0
    cpu_secs = 0.0
    try:
        with open(f"/proc/{pid}/status", "r") as f:
            for line in f:
                if line.startswith("VmHWM:") or line.startswith("VmRSS:"):
                    parts = line.split()
                    rss_mib = max(rss_mib, float(parts[1]) / 1024.0)
    except Exception:
        pass

    try:
        with open(f"/proc/{pid}/stat", "r") as f:
            fields = f.read().split()
            # utime is 13th, stime is 14th (0-indexed)
            utime = int(fields[13])
            stime = int(fields[14])
            ticks_per_sec = os.sysconf(os.sysconf_names['SC_CLK_TCK'])
            cpu_secs = (utime + stime) / ticks_per_sec
    except Exception:
        pass

    return rss_mib, cpu_secs


def measure_latency(target_ip, target_port, rounds=100):
    """Measure TCP round-trip latency in microseconds."""
    rtts = []
    for _ in range(rounds):
        try:
            s = socket.create_connection((target_ip, target_port), timeout=5)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.sendall(b"E")
            payload = b"PING" * 16  # 64 bytes
            t0 = time.perf_counter()
            s.sendall(payload)
            resp = s.recv(len(payload))
            t1 = time.perf_counter()
            s.close()
            if resp == payload:
                rtts.append((t1 - t0) * 1e6)
        except Exception:
            continue
    if not rtts:
        return {"p50": 0, "p95": 0, "p99": 0}
    rtts.sort()
    return {
        "p50": statistics.median(rtts),
        "p95": rtts[int(len(rtts) * 0.95)],
        "p99": rtts[int(len(rtts) * 0.99)],
    }


def measure_throughput_stream(target_ip, target_port, duration_secs):
    """Measure single stream throughput in bytes."""
    try:
        s = socket.create_connection((target_ip, target_port), timeout=10)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.sendall(b"S")
        buf = b"0" * CHUNK
        total_bytes = 0
        t_end = time.time() + duration_secs
        while time.time() < t_end:
            s.sendall(buf)
            total_bytes += len(buf)
        s.close()
        return total_bytes
    except Exception as e:
        return 0


def measure_throughput(target_ip, target_port, concurrency=1, duration_secs=3):
    """Run concurrent streams and return Gbit/s."""
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futs = [pool.submit(measure_throughput_stream, target_ip, target_port, duration_secs) for _ in range(concurrency)]
        total = sum(f.result() for f in futs)
    gbps = (total * 8.0) / (duration_secs * 1e9)
    return gbps, total


def main():
    parser = argparse.ArgumentParser(description="Tachyon TUN Inbound Benchmark")
    parser.add_argument("--bin", default="target/x86_64-unknown-linux-musl/release/tachyon-core", help="Path to tachyon-core binary")
    parser.add_argument("--duration", type=int, default=3, help="Duration per throughput test in seconds")
    parser.add_argument("--out", default="target/bench/tun_result.json", help="Path to JSON output")
    args = parser.parse_args()

    print("=" * 70)
    print("🚀 TACHYON-CORE TUN INBOUND SPEED BENCHMARK (Phase F6)")
    print("=" * 70)

    # 1. Start sink server in background
    import multiprocessing
    sink_proc = multiprocessing.Process(target=run_sink, daemon=True)
    sink_proc.start()
    time.sleep(0.5)

    # 2. Measure Direct Baseline (no proxy, 127.0.0.1 -> Sink)
    print("[1/3] Measuring Direct Loopback Baseline...")
    lat_direct = measure_latency("127.0.0.1", SINK_PORT, rounds=50)
    tp1_direct, _ = measure_throughput("127.0.0.1", SINK_PORT, concurrency=1, duration_secs=args.duration)
    tp8_direct, _ = measure_throughput("127.0.0.1", SINK_PORT, concurrency=8, duration_secs=args.duration)

    print(f"  Direct 1-Stream: {tp1_direct:.2f} Gbit/s | 8-Stream: {tp8_direct:.2f} Gbit/s | p50: {lat_direct['p50']:.1f} µs")

    # Ensure /dev/net/tun device exists
    if not os.path.exists("/dev/net/tun"):
        try:
            os.makedirs("/dev/net", exist_ok=True)
            import stat
            os.mknod("/dev/net/tun", 0o666 | stat.S_IFCHR, os.makedev(10, 200))
        except Exception:
            pass

    # 3. Start tachyon-core with TUN inbound
    print("[2/3] Starting tachyon-core with smoltcp TUN inbound...")
    cfg = {
        "log": {"level": "warn"},
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": TUN_IFNAME,
                "inet4_address": f"{TUN_IP}/30",
                "mtu": 9000,
                "gso": True,
                "auto_route": False
            }
        ],
        "outbounds": [
            {"type": "direct", "tag": "direct-out"}
        ],
        "route": {
            "rules": [
                {
                    "inbound": ["tun-in"],
                    "action": "route",
                    "outbound": "direct-out",
                    "override_address": "127.0.0.1",
                    "override_port": SINK_PORT
                }
            ],
            "final": "direct-out"
        }
    }

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(cfg, f)
        cfg_path = f.name

    core_proc = subprocess.Popen([args.bin, "run", "-c", cfg_path])
    time.sleep(1.0)  # Wait for TUN interface to come up

    try:
        print("[3/3] Benchmarking TUN transparent proxying...")
        _, cpu_start = get_process_metrics(core_proc.pid)

        lat_tun = measure_latency(PEER_IP, SINK_PORT, rounds=50)
        tp1_tun, bytes1 = measure_throughput(PEER_IP, SINK_PORT, concurrency=1, duration_secs=args.duration)
        tp8_tun, bytes8 = measure_throughput(PEER_IP, SINK_PORT, concurrency=8, duration_secs=args.duration)

        rss_peak, cpu_end = get_process_metrics(core_proc.pid)
        total_gib = (bytes1 + bytes8) / (1024.0 ** 3)
        cpu_cost = (cpu_end - cpu_start) / max(total_gib, 0.001)

        result = {
            "direct": {
                "tp_1stream_gbps": round(tp1_direct, 2),
                "tp_8stream_gbps": round(tp8_direct, 2),
                "latency_p50_us": round(lat_direct["p50"], 1),
                "latency_p95_us": round(lat_direct["p95"], 1),
            },
            "tun": {
                "tp_1stream_gbps": round(tp1_tun, 2),
                "tp_8stream_gbps": round(tp8_tun, 2),
                "latency_p50_us": round(lat_tun["p50"], 1),
                "latency_p95_us": round(lat_tun["p95"], 1),
                "peak_rss_mib": round(rss_peak, 2),
                "cpu_cost_s_per_gib": round(cpu_cost, 4),
            }
        }

        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w") as f:
            json.dump(result, f, indent=2)

        print("\n" + "=" * 70)
        print("📊 РЕЗУЛЬТАТЫ БЕНЧМАРКА TUN ИНБАУНДА (tachyon-core vs Direct)")
        print("=" * 70)
        print(f"{'Метрика':<30} | {'Direct (Hardware)':<20} | {'TUN (smoltcp Rust)':<20}")
        print("-" * 75)
        print(f"{'1-Stream Throughput':<30} | {tp1_direct:>14.2f} Gbps | {tp1_tun:>14.2f} Gbps")
        print(f"{'8-Stream Throughput':<30} | {tp8_direct:>14.2f} Gbps | {tp8_tun:>14.2f} Gbps")
        print(f"{'RTT Latency p50':<30} | {lat_direct['p50']:>14.1f} µs   | {lat_tun['p50']:>14.1f} µs")
        print(f"{'RTT Latency p95':<30} | {lat_direct['p95']:>14.1f} µs   | {lat_tun['p95']:>14.1f} µs")
        print(f"{'Peak RSS Memory':<30} | {'—':>17}    | {rss_peak:>14.2f} MiB")
        print(f"{'CPU Cost (s/GiB)':<30} | {'—':>17}    | {cpu_cost:>14.4f} s/GiB")
        print("=" * 75)
        print(f"Отчёт сохранён: {args.out}")

    finally:
        core_proc.terminate()
        try:
            core_proc.wait(timeout=2)
        except Exception:
            core_proc.kill()
        sink_proc.terminate()
        if os.path.exists(cfg_path):
            os.remove(cfg_path)


if __name__ == "__main__":
    main()
