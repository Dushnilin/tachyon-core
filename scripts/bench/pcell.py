#!/usr/bin/env python3
"""One proto.py cell under `perf record`: where does the client spend its time.

    pcell.py --case vmess-ws-tls --impl tachyon --tachyon /bench/tachyon-core \
             --ref /bench/sing-box-lx --streams 1 --out /bench/perf-vmess-ws

The cell is run exactly the way proto.py runs it (same configs, same pinning, same
load generator); the only addition is that the proxy under test is sampled with
`perf record` while the first throughput run of the chosen stream count is going,
and the flat profile is printed afterwards. Needs `perf` in the container and a
binary that still has symbols.
"""
import argparse
import multiprocessing
import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bench  # noqa: E402
import proto  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", required=True)
    ap.add_argument("--impl", default="tachyon", help="which client is profiled: tachyon | ref")
    ap.add_argument("--server", default="", help="tachyon | ref; default follows the part")
    ap.add_argument("--tachyon", required=True)
    ap.add_argument("--ref", required=True)
    ap.add_argument("--streams", type=int, default=1)
    ap.add_argument("--seconds", type=int, default=4)
    ap.add_argument("--target", default="client", help="client | server: which process is sampled")
    ap.add_argument("--out", default="/tmp/pcell")
    ap.add_argument("--top", type=int, default=45)
    ap.add_argument("--callers", default="", help="comma list of symbols to print call chains for")
    ap.add_argument("--pid", action="store_true", help="sample one pid instead of the whole machine")
    ap.add_argument("--graph", action="store_true", help="call-graph sampling (needs an unwinder)")
    ap.add_argument("--strace", default="", help="write a syscall census here instead of profiling")
    ap.add_argument("--comm", default="", help="only count samples of processes with this name")
    args = ap.parse_args()

    cpus = {"client": proto.parse_cpus("0-1"), "server": proto.parse_cpus("2-3")}
    load = set(range(os.cpu_count())) - cpus["client"] - cpus["server"] or cpus["client"]
    os.sched_setaffinity(0, load)
    work = tempfile.mkdtemp()
    certs = proto.make_certs(work)
    reality = proto.make_reality(args.ref)
    ctx = multiprocessing.get_context("fork")
    sink = ctx.Process(target=bench.run_sink, args=(load,), daemon=True)
    sink.start()
    bench.wait_listen(bench.SINK_PORT)
    if reality:
        dest = ctx.Process(target=proto.run_tls_dest, args=(certs, load), daemon=True)
        dest.start()
        bench.wait_listen(proto.REALITY_DEST_PORT)

    case = next(c for c in proto.build_cases(certs, reality) if c["name"] == args.case)
    server_impl = args.server or ("tachyon" if case["part"] == "A" and args.impl == "tachyon" else "ref")
    role = (args.impl, server_impl)

    real = bench.measure_throughput
    state = {"done": False}
    data = args.out + ".data"

    def wrapped(proxy, streams, seconds, pid):
        if state["done"] or streams != args.streams:
            return real(proxy, streams, seconds, pid)
        state["done"] = True
        target = pid
        if args.target == "server":
            target = state["server_pid"]
        # `perf record -p <pid>` writes nothing unless perf_event_paranoid is 1 or
        # lower. Lowering it from a privileged container does work -- it is a
        # host-wide setting and WSL2 shares the kernel with us -- so we do it rather
        # than fall back to sampling the whole machine and filtering by name, which
        # drowns the process of interest in everything else on the box.
        if args.strace:
            # syscall census: needs no unwinder, so it works where perf does not,
            # and it separates "time in the kernel" from "time in our own code"
            # a .raw path asks for the lines themselves: the census of -c hides
            # the sizes, and the size is what names the allocation
            summary = not args.strace.endswith(".raw")
            cmd = ["strace", "-f"] + (["-k"] if args.strace.endswith(".stack") else []) + ["-e", "trace=mmap,munmap"]
            if summary:
                cmd.append("-c")
            st = subprocess.Popen(
                cmd + ["-p", str(target), "-o", args.strace],
                stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            time.sleep(0.5)
            r = real(proxy, streams, seconds, pid)
            time.sleep(0.3)
            st.terminate()
            st.wait()
            print(open(args.strace, errors="replace").read()[:2000])
            if not summary:
                import collections
                import re as _re
                hist = collections.Counter()
                for line in open(args.strace, errors="replace"):
                    m = _re.search(r"mmap\(NULL, (\d+)", line)
                    if m:
                        hist[int(m.group(1))] += 1
                print("mmap size histogram:")
                for size, n in hist.most_common(12):
                    print(f"  {size:>9} bytes : {n}")
            print("measured:", r, flush=True)
            return r
        mode = ["-p", str(target)] if args.pid else ["-a"]
        # let perf finish on its own: killing it leaves the header unwritten and
        # `perf report` then refuses the file ("data size field is 0")
        perf = subprocess.Popen(
            # no -g by default: call-graph sampling needs an unwinder the
            # container kernel does not give us, and perf then records nothing
            ["perf", "record", "-F", "1999", *(["-g"] if args.graph else []),
             "-e", "cpu-clock:u", "-o", data, *mode,
             "--", "sleep", str(seconds + 1)],
            stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        time.sleep(0.5)
        r = real(proxy, streams, seconds, pid)
        perf.wait(timeout=seconds + 30)
        print("measured:", r, flush=True)
        return r

    # Best effort, and host-wide: perf refuses to sample a single process above
    # paranoid 1, and the alternative is profiling everything and filtering after.
    try:
        with open("/proc/sys/kernel/perf_event_paranoid", "w") as f:
            f.write(chr(45) + chr(49) + chr(10))
    except OSError as e:
        print("perf_event_paranoid left alone:", e)

    bench.measure_throughput = wrapped

    # run_cell starts the processes itself; the server pid is needed for
    # --target server, so spy on Proc.start
    orig_start = proto.Proc.start

    def spy(self):
        orig_start(self)
        if self.cfg_path.endswith("server.json"):
            state["server_pid"] = self.p.pid

    proto.Proc.start = spy

    rx, tx = ctx.Pipe(duplex=False)
    ports = (proto.PROXY_PORT_BASE + 1, proto.SERVER_PORT_BASE + 1)
    bins = {"tachyon": args.tachyon, "ref": args.ref}
    cell = ctx.Process(target=proto.run_cell,
                       args=(role, case, bins, cpus, 1, args.seconds, 1500, ports, work, tx))
    cell.start()
    tx.close()
    cell.join(180)
    if cell.is_alive():
        cell.kill()
    res = rx.recv() if rx.poll() else {"status": "FAIL", "why": "no result"}
    print("cell:", {k: res.get(k) for k in ("status", "why", "tput_1", "tput_8", "p50_us")})
    if os.path.exists(data):
        report = ["perf", "report", "-i", data, "--no-children", "--stdio", "-g", "none"]
        if args.comm:
            report += ["--comms", args.comm]
        out = subprocess.run(
            report + ["--sort", "symbol", "--percent-limit", "0.7"],
            capture_output=True, text=True)
        lines = [l for l in out.stdout.splitlines() if l.strip() and not l.startswith("#")]
        print("\n".join(lines[: args.top]))
        for sym in filter(None, args.callers.split(",")):
            out = subprocess.run(
                report + ["--symbols", sym,
                 *(["-g", "caller,0.5,callee,function,percent"] if args.graph else ["-g", "none"]),
                 "--percent-limit", "0.3"],
                capture_output=True, text=True)
            body = [l for l in out.stdout.splitlines() if l.strip() and not l.startswith("#")]
            print(f"--- callers of {sym}")
            print("\n".join(l[:150] for l in body[:40]))


if __name__ == "__main__":
    main()
