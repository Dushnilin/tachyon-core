"""Poor-man's profiler for one proto cell: where a proxy waits and what it costs.

Two passes per binary, with proto.py's exact pinning (client + load generator +
sink on one core, server on the other):

- clean: throughput, CPU of the proxies and of the load generator, context
  switches, and a 5 Hz sample of /proc/<pid>/task/*/stack saying where the
  threads actually sleep;
- strace: `strace -c -f` on both proxy processes, syscall counts per GiB. The
  ptrace stop per syscall wrecks the wall clock here, so numbers from this pass
  are counts only.

Usage: python3 prof.py [--case ss-aes-128-gcm] [--streams 8] [--seconds 12]
                       [--tachyon PATH] [--ref PATH]
"""

import argparse
import collections
import json
import multiprocessing
import os
import signal
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bench  # noqa: E402

SERVER_PORT = 45003

CASES = {
    "ss-aes-128-gcm": {
        "type": "shadowsocks",
        "method": "aes-128-gcm",
        "password": "bench-pass",
    },
}


def write_cfgs(work, case):
    server = {
        "log": {"level": "error"},
        "inbounds": [dict(case, tag="in", listen="127.0.0.1", listen_port=SERVER_PORT)],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"},
    }
    client = {
        "log": {"level": "error"},
        "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1",
                      "listen_port": bench.PROXY_PORT}],
        "outbounds": [dict(case, tag="proxy", server="127.0.0.1", server_port=SERVER_PORT)],
        "route": {"final": "proxy"},
    }
    srv = os.path.join(work, "server.json")
    cli = os.path.join(work, "client.json")
    for path, cfg in ((srv, server), (cli, client)):
        with open(path, "w") as f:
            json.dump(cfg, f)
    return srv, cli


def port_free(port):
    s = socket_socket()
    s.settimeout(0.3)
    try:
        s.connect(("127.0.0.1", port))
        return False
    except OSError:
        return True
    finally:
        s.close()


def socket_socket():
    import socket

    return socket.socket()


def wait_free(port, timeout=10):
    until = time.time() + timeout
    while time.time() < until:
        if port_free(port):
            return True
        time.sleep(0.2)
    return False


def ctxt(pid):
    """Context switches of EVERY thread: /proc/<pid>/status only counts the
    group leader, and in a tokio/Go proxy the leader mostly sleeps."""
    out = {"voluntary_ctxt_switches": 0, "nonvoluntary_ctxt_switches": 0}
    try:
        tids = os.listdir(f"/proc/{pid}/task")
    except OSError:
        return out
    for tid in tids:
        try:
            with open(f"/proc/{pid}/task/{tid}/status") as f:
                for line in f:
                    if line.startswith(("voluntary", "nonvoluntary")):
                        k, v = line.split(":")
                        out[k.strip()] += int(v)
        except (OSError, ValueError):
            continue
    return out


def stacks(pid):
    """One current blocking frame per thread of pid. Needs /proc/pid/task/t/stack."""
    out = collections.Counter()
    try:
        for tid in os.listdir(f"/proc/{pid}/task"):
            try:
                with open(f"/proc/{pid}/task/{tid}/stack") as f:
                    lines = [ln.strip() for ln in f if ln.strip()]
            except OSError:
                continue
            for ln in lines:
                sym = ln.rsplit(" ", 1)[-1]
                if sym and not sym.startswith("[<"):
                    out[sym.split("+")[0]] += 1
                    break
    except OSError:
        pass
    return out


class StackSampler:
    def __init__(self, pids):
        self.pids = pids
        self.samples = collections.Counter()
        self.stop = False
        self.thread = None

    def run(self):
        def loop():
            while not self.stop:
                for pid in self.pids:
                    self.samples.update(stacks(pid))
                time.sleep(0.2)

        self.thread = threading.Thread(target=loop, daemon=True)
        self.thread.start()

    def finish(self):
        self.stop = True
        if self.thread:
            self.thread.join(timeout=2)
        return dict(self.samples.most_common(30))


import threading  # noqa: E402


def ramp_throughput(streams, seconds, step=0.5):
    """bench.measure_throughput but with byte snapshots every `step`, to see
    whether a short window loses to ramp-up or to steady state."""
    total = [0] * streams
    stop = threading.Event()

    def worker(i):
        s = bench.socks_connect(True, bench.MODE_SOURCE)
        buf = bytearray(bench.CHUNK)
        view = memoryview(buf)
        while not stop.is_set():
            n = s.recv_into(view)
            if not n:
                break
            total[i] += n
        s.close()

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(streams)]
    snaps = []
    t0 = time.perf_counter()
    for t in threads:
        t.start()
    while time.perf_counter() - t0 < seconds:
        time.sleep(step)
        snaps.append((time.perf_counter() - t0, sum(total)))
    wall = time.perf_counter() - t0
    stop.set()
    for t in threads:
        t.join(timeout=10)
    got = snaps[-1][1] if snaps else 0
    series = []
    pt, pb = t0, 0
    for (t, b) in snaps:
        series.append({"t": round(t, 2), "gbit": round((b - pb) * 8 / (t - pt) / 1e9, 3)})
        pt, pb = t, b
    return {"gbit_s": got * 8 / wall / 1e9, "series": series}


def run_once(binary, case, client_cpus, server_cpus, streams, seconds, trace):
    if not wait_free(bench.PROXY_PORT) or not wait_free(SERVER_PORT):
        return {"status": "FAIL", "why": "port held before start"}
    load = set(range(os.cpu_count())) - set(client_cpus) - set(server_cpus) or set(client_cpus)
    sink = multiprocessing.Process(target=bench.run_sink, args=(load,), daemon=True)
    sink.start()
    bench.wait_listen(bench.SINK_PORT, timeout=15)
    work = tempfile.mkdtemp(prefix="prof", dir="/tmp")
    srv, cli = write_cfgs(work, case)
    server = subprocess.Popen(
        [binary, "run", "-c", srv],
        start_new_session=True,
        preexec_fn=lambda: os.sched_setaffinity(0, server_cpus),
    )
    bench.wait_listen(SERVER_PORT, timeout=15)
    client = subprocess.Popen(
        [binary, "run", "-c", cli],
        start_new_session=True,
        preexec_fn=lambda: os.sched_setaffinity(0, client_cpus),
    )
    tracers = []
    sampler = None
    res = {"work": work}
    try:
        bench.wait_listen(bench.PROXY_PORT, timeout=15)
        bench.measure_latency(True, 200)
        if trace:
            tracers = [
                subprocess.Popen(
                    ["strace", "-c", "-f", "-p", str(p.pid), "-o", f"{work}/{who}.strace"]
                )
                for who, p in (("server", server), ("client", client), ("sink", sink))
            ]
            tracers.append(
                subprocess.Popen(
                    ["strace", "-c", "-f", "-p", str(os.getpid()),
                     "-o", f"{work}/load.strace"]
                )
            )
            time.sleep(1.5)
        else:
            sampler = StackSampler([client.pid, server.pid, sink.pid, os.getpid()])
            sampler.run()
        c0, s0 = ctxt(client.pid), ctxt(server.pid)
        cu0, cs0 = bench.cpu_split(client.pid)
        su0, ss0 = bench.cpu_split(server.pid)
        ku0, ks0 = bench.cpu_split(sink.pid)
        p0 = time.process_time()
        t0 = time.perf_counter()
        r = ramp_throughput(streams, seconds)
        wall = time.perf_counter() - t0
        p1 = time.process_time()
        c1, s1 = ctxt(client.pid), ctxt(server.pid)
        cu1, cs1 = bench.cpu_split(client.pid)
        su1, ss1 = bench.cpu_split(server.pid)
        ku1, ks1 = bench.cpu_split(sink.pid)
        gib = r["gbit_s"] * 1e9 / 8 * seconds / (1 << 30)
        res.update(
            status="OK",
            gbit_s=r["gbit_s"],
            gib=gib,
            load_cpu_s_per_gib=(p1 - p0) / gib if gib else None,
            client_user=cu1 - cu0,
            client_sys=cs1 - cs0,
            server_user=su1 - su0,
            server_sys=ss1 - ss0,
            sink_user=ku1 - ku0,
            sink_sys=ks1 - ks0,
            series=r.get("series"),
            client_vol=c1.get("voluntary_ctxt_switches", 0) - c0.get("voluntary_ctxt_switches", 0),
            client_invol=c1.get("nonvoluntary_ctxt_switches", 0)
            - c0.get("nonvoluntary_ctxt_switches", 0),
            server_vol=s1.get("voluntary_ctxt_switches", 0) - s0.get("voluntary_ctxt_switches", 0),
            server_invol=s1.get("nonvoluntary_ctxt_switches", 0)
            - s0.get("nonvoluntary_ctxt_switches", 0),
        )
        for k in ("load_cpu_s_per_gib", "client_vol", "client_invol", "server_vol", "server_invol"):
            if res.get(k) is not None and gib:
                res[k + "_per_gib"] = res[k] / gib
        res["raw_ctxt"] = {"c0": c0, "c1": c1, "s0": s0, "s1": s1}
        if sampler:
            res["sleep"] = sampler.finish()
    except Exception as e:  # noqa: BLE001
        res.update(status="FAIL", why=f"{type(e).__name__}: {e}")
    finally:
        if sampler:
            sampler.finish()
        for t in tracers:
            t.send_signal(signal.SIGINT)
            try:
                t.wait(timeout=5)
            except subprocess.TimeoutExpired:
                t.kill()
        for p in (client, server):
            if p.poll() is None:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        if sink.is_alive():
            sink.terminate()
        time.sleep(0.5)
        for p in (client, server):
            if p.poll() is None:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        for p in (client, server):
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        sink.join(timeout=3)
        time.sleep(0.5)
    for who in ("server", "client", "sink", "load"):
        path = f"{work}/{who}.strace"
        if os.path.exists(path):
            with open(path) as f:
                res[who + "_strace"] = f.read()
    wait_free(bench.PROXY_PORT, timeout=5)
    wait_free(SERVER_PORT, timeout=5)
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", default="ss-aes-128-gcm")
    ap.add_argument("--streams", type=int, default=8)
    ap.add_argument("--seconds", type=float, default=12)
    ap.add_argument("--tachyon", default="/tmp/bench/tachyon-core")
    ap.add_argument("--ref", default="/usr/bin/sing-box")
    ap.add_argument("--only", choices=("tachyon", "ref"))
    ap.add_argument("--skip-strace", action="store_true")
    args = ap.parse_args()

    case = CASES[args.case]
    out = {}
    for name, binary in (("tachyon", args.tachyon), ("ref", args.ref)):
        if args.only and name != args.only:
            continue
        out[name] = {
            "clean": run_once(
                binary, case, {0}, {1}, args.streams, args.seconds, trace=False,
            ),
        }
        if not args.skip_strace:
            out[name]["strace"] = run_once(
                binary, case, {0}, {1}, args.streams, args.seconds, trace=True,
            )
        print(f"# {name} done", file=sys.stderr)
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
