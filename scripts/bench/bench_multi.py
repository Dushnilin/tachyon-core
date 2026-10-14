#!/usr/bin/env python3
"""Fast, objective multi-core benchmark: tachyon-core vs sing-box vs Xray vs Mihomo.

Measures:
  1. Binary size (MiB on disk)
  2. Cold start latency (ms to accepting connections)
  3. Idle RSS (MiB)
  4. Latency RTT (p50, p95, p99 in microseconds for 64-byte echo)
  5. Single-stream throughput (Gbps) & CPU cost (proxy CPU-seconds / GiB)
  6. Multi-stream throughput (8 streams, Gbps) & CPU cost (s/GiB)
  7. C1K connection scale (RSS with 1,000 idle connections open, MiB)
  8. Peak memory under load (VmHWM, MiB)

Strict isolation:
  Proxy is pinned to PROXY_CPUS (e.g. core 1 for router profile).
  Load generator and Sink server are pinned to LOAD_CPUS (e.g. core 0).
  Load generator NEVER robs CPU from the proxy under test.
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
CHUNK = 1 << 20  # 1 MiB

MODE_HOLD, MODE_ECHO, MODE_SOURCE, MODE_SINK = b"H", b"E", b"S", b"K"


# ---------------------------------------------------------------- sink server
def run_sink(cpus):
    if hasattr(os, "sched_setaffinity"):
        os.sched_setaffinity(0, cpus)

    async def handle(r, w):
        try:
            mode = await r.readexactly(1)
            if mode == MODE_HOLD or mode == MODE_SINK:
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


# ------------------------------------------------------------------ SOCKS5 client
def socks_connect(proxy, mode):
    s = socket.create_connection(("127.0.0.1", PROXY_PORT if proxy else SINK_PORT), timeout=30)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    if proxy:
        s.sendall(b"\x05\x01\x00")
        auth = recvn(s, 2)
        assert auth == b"\x05\x00", f"socks auth failed: {auth!r}"
        s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", SINK_PORT))
        reply = recvn(s, 10)
        assert reply[1] == 0, f"socks connect refused: {reply!r}"
    s.sendall(mode)
    return s


def recvn(s, n):
    out = b""
    while len(out) < n:
        chunk = s.recv(n - len(out))
        if not chunk:
            raise ConnectionError("eof")
        out += chunk
    return out


async def async_socks_connect(proxy, mode):
    host, port = "127.0.0.1", PROXY_PORT if proxy else SINK_PORT
    r, w = await asyncio.open_connection(host, port)
    if proxy:
        w.write(b"\x05\x01\x00")
        auth = await r.readexactly(2)
        assert auth == b"\x05\x00", f"socks auth failed: {auth!r}"
        w.write(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", SINK_PORT))
        reply = await r.readexactly(10)
        assert reply[1] == 0, f"socks connect refused: {reply!r}"
    w.write(mode)
    return r, w


# ------------------------------------------------------------------ proc info
def get_proc_tree_pids(pid):
    pids = [pid]
    try:
        task_dir = f"/proc/{pid}/task"
        if os.path.exists(task_dir):
            for tid in os.listdir(task_dir):
                cf = os.path.join(task_dir, tid, "children")
                if os.path.exists(cf):
                    with open(cf) as f:
                        for c in f.read().split():
                            pids.extend(get_proc_tree_pids(int(c)))
    except Exception:
        pass
    return list(dict.fromkeys(pids))


def proc_status(pid):
    out = {"VmRSS": 0.0, "VmHWM": 0.0}
    for p in get_proc_tree_pids(pid):
        try:
            with open(f"/proc/{p}/status") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        out["VmRSS"] += int(line.split(":")[1].split()[0]) / 1024
                    elif line.startswith("VmHWM:"):
                        out["VmHWM"] += int(line.split(":")[1].split()[0]) / 1024
        except Exception:
            pass
    return out


def cpu_split(pid):
    """(user, system) seconds from /proc/<pid>/stat for pid and all child processes."""
    user, system = 0.0, 0.0
    tick = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
    for p in get_proc_tree_pids(pid):
        try:
            with open(f"/proc/{p}/stat") as f:
                fields = f.read().rsplit(")", 1)[1].split()
            user += int(fields[11]) / tick
            system += int(fields[12]) / tick
        except Exception:
            pass
    return user, system


def kill_proc_tree(proc):
    try:
        pids = get_proc_tree_pids(proc.pid)
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
        for p in pids:
            if p != proc.pid:
                try:
                    os.kill(p, signal.SIGTERM)
                except OSError:
                    pass
    except Exception:
        pass


# -------------------------------------------------------------------- measurement phases
def measure_latency(proxy, rounds=5000):
    s = socks_connect(proxy, MODE_ECHO)
    msg = b"x" * 64
    for _ in range(50):  # warm-up
        s.sendall(msg)
        recvn(s, 64)
    samples = []
    for _ in range(rounds):
        t = time.perf_counter_ns()
        s.sendall(msg)
        assert recvn(s, 64) == msg, "echo corrupted"
        samples.append((time.perf_counter_ns() - t) / 1000)
    s.close()
    samples.sort()
    return {
        "p50_us": round(samples[len(samples) // 2], 1),
        "p95_us": round(samples[int(len(samples) * 0.95)], 1),
        "p99_us": round(samples[int(len(samples) * 0.99)], 1),
    }


def measure_throughput(proxy, streams, seconds, pid):
    """Download throughput: sink pushes, client reads."""
    total = [0] * streams
    stop = threading.Event()

    def worker(i):
        try:
            s = socks_connect(proxy, MODE_SOURCE)
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
    return {
        "gbit_s": round(got * 8 / elapsed / 1e9, 2),
        "gib": round(gib, 3),
        "proxy_cpu_s_per_gib": per_gib,
    }


def hold_connections(proxy, count, pid):
    """Open `count` idle proxied connections and report proxy RSS."""
    async def run():
        conns = []
        batch_size = 200
        for batch in range(0, count, batch_size):
            cur = min(batch_size, count - batch)
            got = await asyncio.gather(
                *(async_socks_connect(proxy, MODE_HOLD) for _ in range(cur)),
                return_exceptions=True
            )
            for res in got:
                if not isinstance(res, Exception):
                    conns.append(res)
        await asyncio.sleep(1.0)
        rss = proc_status(pid)["VmRSS"] if pid else None
        for r, w in conns:
            w.close()
        await asyncio.sleep(0.5)
        return round(rss, 1) if rss is not None else None

    try:
        return asyncio.run(run())
    except Exception as e:
        print(f"hold_connections({count}) failed: {e}", file=sys.stderr)
        return None


def wait_port_free(port, timeout=5):
    t0 = time.perf_counter()
    while time.perf_counter() - t0 < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.05):
                time.sleep(0.05)
        except OSError:
            return


def wait_listen(port, proc=None, timeout=15):
    t0 = time.perf_counter()
    while time.perf_counter() - t0 < timeout:
        if proc and proc.poll() is not None:
            raise RuntimeError(f"process exited prematurely with code {proc.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return (time.perf_counter() - t0) * 1000
        except OSError:
            time.sleep(0.003)
    raise TimeoutError(f"nothing listening on {port}")


# ------------------------------------------------------------------ configurations
def ensure_steer_env(bin_path):
    """Sets up musl libc symlink, all steer* binaries in /usr/sbin, and libsteer* in /usr/lib."""
    try:
        need_musl = not os.path.exists("/lib/ld-musl-x86_64.so.1")
        need_ip = not (os.path.exists("/sbin/ip") or os.path.exists("/usr/sbin/ip") or os.path.exists("/bin/ip"))
        need_nft = not (os.path.exists("/usr/sbin/nft") or os.path.exists("/sbin/nft"))
        if need_musl or need_ip or need_nft:
            subprocess.run(["apt-get", "update", "-qq"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            pkgs = []
            if need_musl:
                pkgs.append("musl")
            if need_ip:
                pkgs.append("iproute2")
            if need_nft:
                pkgs.append("nftables")
            subprocess.run(["apt-get", "install", "-y", "-qq"] + pkgs, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        os.makedirs("/usr/sbin", exist_ok=True)
        os.makedirs("/usr/lib", exist_ok=True)
        os.makedirs("/usr/lib/x86_64-linux-musl", exist_ok=True)

        if os.path.exists("/lib/ld-musl-x86_64.so.1") and not os.path.exists("/usr/lib/libc.so"):
            try:
                os.symlink("/lib/ld-musl-x86_64.so.1", "/usr/lib/libc.so")
            except OSError:
                pass

        bin_dir = os.path.dirname(os.path.abspath(bin_path))
        steer_base = os.path.dirname(bin_dir)  # e.g. /bench/steer/usr

        sbin_dirs = [
            os.path.join(bin_dir, "..", "sbin"),
            os.path.join(steer_base, "sbin"),
            os.path.join(os.path.dirname(steer_base), "usr", "sbin"),
            bin_dir,
        ]
        for sdir in sbin_dirs:
            if os.path.exists(sdir):
                for name in os.listdir(sdir):
                    if name == "steerd" or name == "steer" or name.startswith("steer-"):
                        src = os.path.abspath(os.path.join(sdir, name))
                        if os.path.isfile(src):
                            try:
                                os.chmod(src, 0o755)
                            except OSError:
                                pass
                            dst = f"/usr/sbin/{name}"
                            if not os.path.exists(dst):
                                try:
                                    os.symlink(src, dst)
                                except OSError:
                                    pass

        lib_candidates = [
            os.path.join(bin_dir, "..", "lib"),
            os.path.join(steer_base, "lib"),
            os.path.join(os.path.dirname(steer_base), "usr", "lib"),
            os.path.join(bin_dir, "lib"),
        ]
        for ldir in lib_candidates:
            if os.path.exists(ldir):
                for f in os.listdir(ldir):
                    src = os.path.abspath(os.path.join(ldir, f))
                    for target_dir in ("/usr/lib", "/usr/lib/x86_64-linux-musl"):
                        dst = os.path.join(target_dir, f)
                        if not os.path.exists(dst):
                            try:
                                os.symlink(src, dst)
                            except OSError:
                                pass
    except Exception as e:
        print(f"Warning: ensure_steer_env error: {e}", file=sys.stderr)


def setup_proxy(name, bin_path, proxy_cpus, workers=None):
    """Generates config and launches proxy process, returns (proc, temp_dir, start_ms)."""
    d = tempfile.mkdtemp(prefix=f"bench_{name}_")
    env = os.environ.copy()
    if workers:
        env["TACHYON_WORKERS"] = str(workers)
        env["GOMAXPROCS"] = str(workers)

    preexec = (lambda: os.sched_setaffinity(0, proxy_cpus)) if hasattr(os, "sched_setaffinity") else None

    if name in ("tachyon", "tachyon-core", "sing-box"):
        cfg_path = os.path.join(d, "config.json")
        cfg = {
            "log": {"level": "error"},
            "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": PROXY_PORT}],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct"},
        }
        with open(cfg_path, "w") as f:
            json.dump(cfg, f)
        cmd = [bin_path, "run", "-c", cfg_path]

    elif name in ("steer", "steer-box-connector"):
        ensure_steer_env(bin_path)
        cfg_path = os.path.join(d, "config.json")
        cfg = {
            "log": {"level": "error"},
            "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": PROXY_PORT}],
            "outbounds": [{"type": "direct", "tag": "direct", "bind_interface": "lo"}],
            "route": {"final": "direct"},
        }
        with open(cfg_path, "w") as f:
            json.dump(cfg, f)
        cmd = [bin_path, "run", "-c", cfg_path]
        curr_ld = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = f"/usr/lib:{curr_ld}" if curr_ld else "/usr/lib"

    elif name in ("xray", "xray-core"):
        cfg_path = os.path.join(d, "config.json")
        cfg = {
            "log": {"loglevel": "error"},
            "inbounds": [
                {
                    "listen": "127.0.0.1",
                    "port": PROXY_PORT,
                    "protocol": "socks",
                    "settings": {"auth": "noauth", "udp": False},
                }
            ],
            "outbounds": [{"protocol": "freedom", "tag": "direct"}],
        }
        with open(cfg_path, "w") as f:
            json.dump(cfg, f)
        cmd = [bin_path, "run", "-c", cfg_path]

    elif name in ("mihomo", "clash"):
        cfg_path = os.path.join(d, "config.yaml")
        yaml_content = f"""mixed-port: {PROXY_PORT}
mode: direct
log-level: silent
ipv6: false
external-controller: ""
profile:
  store-selected: false
"""
        with open(cfg_path, "w") as f:
            f.write(yaml_content)
        cmd = [bin_path, "-d", d, "-f", cfg_path]
    else:
        raise ValueError(f"unknown proxy type: {name}")

    t0 = time.perf_counter()
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
        preexec_fn=preexec,
    )
    start_ms = wait_listen(PROXY_PORT, proc)
    return proc, d, start_ms


def get_binary_size(name, bin_path):
    if name in ("steer", "steer-box-connector"):
        total = 0
        bin_dir = os.path.dirname(os.path.abspath(bin_path))
        candidates = [
            bin_path,
            os.path.join(bin_dir, "..", "sbin", "steerd"),
            os.path.join(bin_dir, "..", "sbin", "steer"),
            os.path.join(bin_dir, "..", "lib", "libsteer.so.2.0.3"),
            "/usr/sbin/steerd",
            "/usr/sbin/steer",
            "/usr/lib/libsteer.so.2.0.3",
        ]
        seen = set()
        for candidate in candidates:
            if os.path.exists(candidate) and os.path.realpath(candidate) not in seen:
                seen.add(os.path.realpath(candidate))
                total += os.path.getsize(candidate)
        if total > 0:
            return round(total / (1 << 20), 2)
    return round(os.path.getsize(bin_path) / (1 << 20), 2)


def get_version(name, bin_path):
    try:
        env = os.environ.copy()
        if name in ("steer", "steer-box-connector"):
            ensure_steer_env(bin_path)
            curr_ld = env.get("LD_LIBRARY_PATH", "")
            env["LD_LIBRARY_PATH"] = f"/usr/lib:{curr_ld}" if curr_ld else "/usr/lib"
        if name in ("mihomo", "clash"):
            out = subprocess.run([bin_path, "-v"], capture_output=True, text=True, timeout=5, env=env).stdout
        else:
            out = subprocess.run([bin_path, "version"], capture_output=True, text=True, timeout=5, env=env).stdout
        lines = [line.strip() for line in out.splitlines() if line.strip()]
        if name in ("steer", "steer-box-connector"):
            for l in lines:
                if "steer-box-connector" in l:
                    return l.replace("Environment: ", "")
        return lines[0] if lines else "?"
    except Exception:
        return "?"


# ------------------------------------------------------------------ runner
def bench_one(name, bin_path, proxy_cpus, args):
    print(f"\n>>> Benchmarking [{name}] ({bin_path}) ...", flush=True)
    if name in ("steer", "steer-box-connector"):
        ensure_steer_env(bin_path)
    res = {
        "name": name,
        "bin": bin_path,
        "size_mib": get_binary_size(name, bin_path),
        "version": get_version(name, bin_path),
    }

    # Cold start measurement (3 runs)
    starts = []
    for _ in range(3):
        p, d, s_ms = setup_proxy(name, bin_path, proxy_cpus, args.workers)
        starts.append(s_ms)
        kill_proc_tree(p)
        wait_port_free(PROXY_PORT)
        time.sleep(0.1)
    res["start_ms"] = round(statistics.median(starts), 1)

    # Main measurement run
    proc, d, _ = setup_proxy(name, bin_path, proxy_cpus, args.workers)
    try:
        time.sleep(1.0)
        res["idle_rss_mib"] = round(proc_status(proc.pid)["VmRSS"], 1)

        print(f"  [{name}] Latency ({args.latency_rounds} rounds)...", flush=True)
        res["latency"] = measure_latency(True, args.latency_rounds)

        print(f"  [{name}] Throughput 1-stream ({args.seconds}s)...", flush=True)
        res["tput_1"] = measure_throughput(True, 1, args.seconds, proc.pid)

        print(f"  [{name}] Throughput 8-streams ({args.seconds}s)...", flush=True)
        res["tput_8"] = measure_throughput(True, 8, args.seconds, proc.pid)

        if not args.no_c1k:
            print(f"  [{name}] Concurrency C1K (1000 idle conns)...", flush=True)
            res["c1k_rss_mib"] = hold_connections(True, 1000, proc.pid)
        else:
            res["c1k_rss_mib"] = None

        res["peak_rss_mib"] = round(proc_status(proc.pid)["VmHWM"], 1)

    finally:
        kill_proc_tree(proc)
        wait_port_free(PROXY_PORT)

    return res


def print_table(results, direct):
    print("\n" + "=" * 115)
    print("  FAST & OBJECTIVE PROXY CORE BENCHMARK (Tachyon vs Sing-box vs Xray vs Mihomo vs Steer)")
    print("=" * 115)
    header = f"{'Proxy':<14} | {'Size':<7} | {'Start':<8} | {'Idle RSS':<9} | {'p50 us':<7} | {'p99 us':<7} | {'1s Gbps':<8} | {'8s Gbps':<8} | {'CPU s/GiB':<10} | {'C1K RSS':<8} | {'Peak RSS':<8}"
    print(header)
    print("-" * 115)

    if direct:
        d_p50 = f"{direct['latency']['p50_us']} us"
        d_p99 = f"{direct['latency']['p99_us']} us"
        d_1s = f"{direct['tput_1']['gbit_s']}"
        d_8s = f"{direct['tput_8']['gbit_s']}"
        print(f"{'DIRECT (baseline)':<14} | {'-':<7} | {'-':<8} | {'-':<9} | {d_p50:<7} | {d_p99:<7} | {d_1s:<8} | {d_8s:<8} | {'0.000':<10} | {'-':<8} | {'-':<8}")
        print("-" * 115)

    for r in results:
        name = r["name"]
        sz = f"{r['size_mib']}M"
        start = f"{r['start_ms']} ms"
        idle = f"{r['idle_rss_mib']}M"
        p50 = f"{r['latency']['p50_us']}"
        p99 = f"{r['latency']['p99_us']}"
        t1 = f"{r['tput_1']['gbit_s']}"
        t8 = f"{r['tput_8']['gbit_s']}"
        cpu = f"{r['tput_8']['proxy_cpu_s_per_gib'] or r['tput_1']['proxy_cpu_s_per_gib'] or '-'}"
        c1k = f"{r['c1k_rss_mib']}M" if r.get("c1k_rss_mib") is not None else "-"
        peak = f"{r['peak_rss_mib']}M"
        print(f"{name:<14} | {sz:<7} | {start:<8} | {idle:<9} | {p50:<7} | {p99:<7} | {t1:<8} | {t8:<8} | {cpu:<10} | {c1k:<8} | {peak:<8}")

    print("=" * 115)


def generate_html(data, out_path):
    results = data["results"]
    direct = data.get("direct", {})
    rows = ""
    for r in results:
        rows += f"""
        <tr>
          <td><strong>{r['name']}</strong><br><small style="color:#888">{r['version'][:40]}</small></td>
          <td>{r['size_mib']} MiB</td>
          <td>{r['start_ms']} ms</td>
          <td>{r['idle_rss_mib']} MiB</td>
          <td>{r['latency']['p50_us']} µs</td>
          <td>{r['latency']['p99_us']} µs</td>
          <td class="num bold">{r['tput_1']['gbit_s']}</td>
          <td class="num bold">{r['tput_8']['gbit_s']}</td>
          <td>{r['tput_8']['proxy_cpu_s_per_gib']} s/GiB</td>
          <td>{r.get('c1k_rss_mib', '-')} MiB</td>
          <td>{r['peak_rss_mib']} MiB</td>
        </tr>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>Proxy Core Benchmark: Tachyon vs Sing-box vs Xray vs Mihomo vs Steer</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; background: #0f1117; color: #e1e4e8; padding: 24px; }}
  h1 {{ font-size: 20px; margin-bottom: 4px; color: #58a6ff; }}
  .subtitle {{ font-size: 13px; color: #8b949e; margin-bottom: 20px; }}
  table {{ border-collapse: collapse; width: 100%; max-width: 1100px; background: #161b22; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.5); }}
  th, td {{ padding: 10px 14px; text-align: left; border-bottom: 1px solid #30363d; font-size: 13px; }}
  th {{ background: #21262d; color: #c9d1d9; font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; }}
  tr:hover {{ background: #1f242c; }}
  .num {{ font-family: monospace; font-size: 14px; }}
  .bold {{ font-weight: bold; color: #3fb950; }}
  .meta {{ margin-top: 16px; font-size: 12px; color: #8b949e; }}
</style>
</head>
<body>
  <h1>Сравнительный бенчмарк прокси-ядер</h1>
  <div class="subtitle">Сквозное тестирование: SOCKS5 Inbound → Direct Outbound. CPU Profile: {data['profile']} (proxy: {data['proxy_cpus']})</div>
  <table>
    <thead>
      <tr>
        <th>Ядро</th>
        <th>Размер</th>
        <th>Старт</th>
        <th>Idle RAM</th>
        <th>p50 Lat</th>
        <th>p99 Lat</th>
        <th>1 stream</th>
        <th>8 streams</th>
        <th>CPU на GiB</th>
        <th>C1K RAM</th>
        <th>Peak RAM</th>
      </tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>
  <div class="meta">
    Платформа: {data.get('cpu', '?')} | Ядро Linux: {data.get('kernel', '?')} | Сгенерировано: {time.strftime('%Y-%m-%d %H:%M:%S')}
  </div>
</body>
</html>
"""
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html_content)


def main():
    ap = argparse.ArgumentParser(description="Multi-proxy fast benchmark runner")
    ap.add_argument("--tachyon", default="/bench/tachyon-core")
    ap.add_argument("--sing-box", default="/bench/sing-box-lx")
    ap.add_argument("--xray", default="/bench/xray-linux")
    ap.add_argument("--mihomo", default="/bench/mihomo-linux")
    ap.add_argument("--steer", default=None, help="Path to steer-box-connector binary")
    ap.add_argument("--profile", choices=["router", "desktop"], default="router")
    ap.add_argument("--proxy-cpus", default=None, help="Explicit CPU set (e.g. '1')")
    ap.add_argument("--workers", type=int, default=None, help="Thread count (1 for router)")
    ap.add_argument("--seconds", type=int, default=2, help="Seconds per throughput test (default 2)")
    ap.add_argument("--latency-rounds", type=int, default=5000, help="Echo latency iterations")
    ap.add_argument("--no-c1k", action="store_true", help="Skip 1000 connection hold test for ultra-fast run")
    ap.add_argument("--only", help="Comma-separated proxy list to run (e.g. tachyon,xray)")
    ap.add_argument("--out", default="/bench/multi-bench.json")
    ap.add_argument("--html", default="/bench/multi-bench.html")
    args = ap.parse_args()

    # CPU allocation
    all_cpus = set(range(os.cpu_count() or 1))
    if args.proxy_cpus:
        proxy_cpus = {int(x) for x in args.proxy_cpus.split(",")}
    elif args.profile == "router":
        proxy_cpus = {1} if len(all_cpus) > 1 else {0}
        if args.workers is None:
            args.workers = 1
    else:  # desktop
        proxy_cpus = {0, 1} if len(all_cpus) >= 4 else {0}

    load_cpus = all_cpus - proxy_cpus or proxy_cpus
    if hasattr(os, "sched_setaffinity"):
        os.sched_setaffinity(0, load_cpus)

    print(f"=== Starting Multi-Proxy Benchmark ({args.profile.upper()} profile) ===")
    print(f"CPUs: proxy={proxy_cpus}, load/sink={load_cpus}, workers={args.workers}")

    # Launch sink server
    sink = multiprocessing.Process(target=run_sink, args=(load_cpus,), daemon=True)
    sink.start()
    wait_listen(SINK_PORT)

    # Baseline direct test (no proxy)
    print("Measuring DIRECT hardware baseline ...", flush=True)
    direct = {
        "latency": measure_latency(False, args.latency_rounds),
        "tput_1": measure_throughput(False, 1, args.seconds, None),
        "tput_8": measure_throughput(False, 8, args.seconds, None),
    }

    proxies = [
        ("tachyon", args.tachyon),
        ("sing-box", args.sing_box),
        ("xray", args.xray),
        ("mihomo", args.mihomo),
    ]

    steer_bin = args.steer
    if not steer_bin:
        for candidate in [
            "/bench/steer/usr/bin/sing-box",
            "/bench/steer/sing-box",
            "/opt/steer/usr/bin/sing-box",
        ]:
            if os.path.exists(candidate):
                steer_bin = candidate
                break

    if steer_bin:
        proxies.append(("steer", steer_bin))

    if args.only:
        allowed = set(args.only.split(","))
        proxies = [p for p in proxies if p[0] in allowed]

    results = []
    for name, path in proxies:
        if not os.path.exists(path):
            print(f"Skipping {name}: binary not found at {path}")
            continue
        try:
            r = bench_one(name, path, proxy_cpus, args)
            results.append(r)
        except Exception as e:
            print(f"ERROR benchmarking {name}: {e}", file=sys.stderr)

    print_table(results, direct)

    out_data = {
        "profile": args.profile,
        "proxy_cpus": list(proxy_cpus),
        "workers": args.workers,
        "cpu": next((l.split(":")[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name")), "?"),
        "kernel": os.uname().release if hasattr(os, "uname") else "?",
        "direct": direct,
        "results": results,
    }

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(out_data, f, indent=2)
        print(f"\nSaved JSON: {args.out}")

    if args.html:
        generate_html(out_data, args.html)
        print(f"Saved HTML: {args.html}")

    sink.terminate()


if __name__ == "__main__":
    main()
