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
    ap.add_argument("--kernel", action="store_true",
                    help="cpu-clock without :u — user and kernel samples both")
    ap.add_argument("--stat", action="store_true",
                    help="count syscalls of the target for the first run instead of sampling")
    ap.add_argument("--sched", action="store_true",
                    help="off-cpu view for the first run: per-thread sleep/run and wakeup pairs")
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
    data = "/tmp/pcell-perf.data"
    keep = args.out + ".data"

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
        if args.stat:
            # counts, not timings: how many sendto/recvfrom a GiB actually
            # costs. Needs tracefs, which a privileged container has to mount.
            import signal
            out = args.strace or (args.out + ".stat")
            subprocess.run(["mount", "-t", "tracefs", "tracefs", "/sys/kernel/tracing"],
                           capture_output=True)
            ps = subprocess.Popen(
                ["perf", "stat", "-x,", "-p", str(target), "-o", out,
                 "-e", "syscalls:sys_enter_sendto,syscalls:sys_enter_recvfrom,"
                       "syscalls:sys_enter_epoll_pwait,syscalls:sys_enter_write,"
                       "syscalls:sys_enter_read,syscalls:sys_enter_futex,"
                       "syscalls:sys_enter_writev,syscalls:sys_enter_sendmsg,"
                       "syscalls:sys_enter_readv,syscalls:sys_enter_recvmsg"],
                stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            time.sleep(0.5)
            r = real(proxy, streams, seconds, pid)
            time.sleep(0.3)
            ps.send_signal(signal.SIGINT)
            ps.wait()
            print(open(out, errors="replace").read(), flush=True)
            return r
        if args.sched:
            # off-cpu: where the wall clock goes when the process is not on a
            # CPU. sched record is system-wide (tracepoints have no per-pid
            # filter at record time), timehist is filtered by pid afterwards.
            # The data file stays in /tmp: perf finalizes its size header via
            # fallocate, which fails on the drvfs bind mount and leaves the
            # file unreadable ("data size field is 0").
            import re as _re
            import shutil
            raw = "/tmp/pcell-sched.data"
            subprocess.run(["mount", "-t", "tracefs", "tracefs", "/sys/kernel/tracing"],
                           capture_output=True)
            ps = subprocess.Popen(
                ["perf", "sched", "record", "-o", raw, "--", "sleep", str(seconds + 1)],
                stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            time.sleep(0.5)
            r = real(proxy, streams, seconds, pid)
            ps.wait(timeout=seconds + 60)
            shutil.copy(raw, args.out + ".sched")
            th = subprocess.run(["perf", "sched", "timehist", "-i", raw, "-n", "-w"],
                                capture_output=True, text=True)
            sw = _re.compile(r"^\s*(\d+\.\d+)\s+\[\d+\]\s+(\S+)\[(\d+)/(\d+)\]"
                             r"\s+(\S+)\s+(\S+)\s+(\S+)\s+next: (\S+)\[(\d+)\]")
            wk = _re.compile(r"^\s*(\d+\.\d+)\s+\[\d+\]\s+(\S+)\[(\d+)/(\d+)\]"
                             r"\s+awakened: :?(\d+)")
            run = {}
            wait = {}
            sleeps = {}
            last_out = {}
            comm = {}
            ours = set()
            wakes = {}
            for line in th.stdout.splitlines():
                m = sw.match(line)
                if m:
                    t, prev, tid, pidn, w, sd, rt, nxt, ntid = m.groups()
                    tid, pidn, ntid = int(tid), int(pidn), int(ntid)
                    comm.setdefault(tid, prev)
                    comm.setdefault(ntid, nxt)
                    if pidn == target:
                        ours.add(tid)
                        ours.add(ntid)
                        # the run/wait columns are already in msec
                        run[tid] = run.get(tid, 0.0) + float(rt)
                        wait[tid] = wait.get(tid, 0.0) + float(sd)
                        last_out[tid] = float(t)
                    if ntid in last_out:
                        # tids are in seconds; a thread that switched out and
                        # back in was off-cpu for exactly this long
                        sl = float(t) - last_out.pop(ntid)
                        if sl >= 0:
                            sleeps.setdefault(ntid, []).append(sl)
                    continue
                m = wk.match(line)
                if m:
                    t, wcomm, wtid, wp, wak = m.groups()
                    wak = int(wak)
                    wtid = int(wtid)
                    if wak in ours or wtid in ours:
                        key = (wcomm, wtid, comm.get(wak, "?"), wak)
                        wakes[key] = wakes.get(key, 0) + 1
            print(f"=== sched target pid {target} ({seconds}s window; run/wait msec, sleep sec)")
            print(f"{'tid':>6} {'comm':<15} {'run':>9} {'sleeps':>7} "
                  f"{'avg':>8} {'p50':>8} {'p95':>8} {'max':>8} {'schdel':>8}")
            for tid in sorted(run, key=lambda k: -run.get(k, 0)):
                ss = sorted(sleeps.get(tid, []))
                n = len(ss)
                avg = sum(ss) / n if n else 0
                p50 = ss[n // 2] if n else 0
                p95 = ss[int(n * 0.95)] if n else 0
                mx = ss[-1] if n else 0
                print(f"{tid:>6} {comm.get(tid, '?'):<15} {run.get(tid, 0):>9.1f} "
                      f"{n:>7} {avg * 1e3:>8.3f} {p50 * 1e3:>8.3f} {p95 * 1e3:>8.3f} "
                      f"{mx * 1e3:>8.3f} {wait.get(tid, 0):>8.1f}")
            print("--- wakeups touching target threads (waker -> wakee, count)")
            for key, n in sorted(wakes.items(), key=lambda kv: -kv[1])[:15]:
                wc, wt, tc, tt = key
                print(f"  {wc}[{wt}] -> {tc}[{tt}] : {n}")
            print("measured:", r, flush=True)
            return r
        if args.strace:
            # syscall census: needs no unwinder, so it works where perf does not,
            # and it separates "time in the kernel" from "time in our own code".
            # A .raw path asks for the lines themselves: the census of -c hides
            # the sizes, and the size is what names the allocation. ".all" in the
            # name drops the mmap filter, for the full syscall view. -T is always
            # on: with -c it is ignored, with .raw it is the whole point.
            # `.stack` asks for per-call backtraces, which -c cannot print.
            summary = not args.strace.endswith((".raw", ".stack", ".send", ".recv", ".read", ".tick"))
            cmd = ["strace", "-f", "-T"] + (["-k"] if args.strace.endswith(".stack") else [])
            if ".all" in args.strace:
                pass
            elif args.strace.endswith(".tick"):
                # relative timestamps + syscall duration: the wall-clock gaps
                # between events are where a stalled pipeline shows up
                cmd += ["-r", "-T", "-s", "0",
                        "-e", "trace=epoll_pwait,recvfrom,sendto,write,read,futex"]
            elif args.strace.endswith((".send", ".recv", ".read")):
                # -s 0 keeps payload bytes out of the lines: the length is the
                # third argument and stays parseable
                cmd += ["-s", "0", "-e", "trace=sendto,recvfrom,read,write"]
            else:
                cmd += ["-e", "trace=mmap,munmap"]
            if summary:
                cmd.append("-c")
            st = subprocess.Popen(
                cmd + ["-p", str(target), "-o", args.strace],
                stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            time.sleep(0.5)
            r = real(proxy, streams, seconds, pid)
            time.sleep(0.3)
            # SIGINT, not SIGTERM: strace -c only writes the summary when it is
            # interrupted, and a plain terminate leaves the file empty
            import signal
            st.send_signal(signal.SIGINT)
            st.wait()
            print(open(args.strace, errors="replace").read()[:2000])
            if not summary:
                import collections
                import re as _re
                hist = collections.Counter()
                call = (
                    "sendto" if args.strace.endswith(".send")
                    else "recvfrom" if args.strace.endswith(".recv")
                    else "read" if args.strace.endswith(".read")
                    else "mmap"
                )
                if not args.strace.endswith((".send", ".recv", ".read")):
                    pats = [_re.escape(call) + r"\(NULL, (\d+)"]
                else:
                    # sendto/recvfrom have args after the size, read does not;
                    # strace -f splits a line into unfinished/resumed halves and
                    # the resumed half carries buf, size
                    pats = [
                        _re.escape(call) + r"\([^,]+, [^,]+, (\d+)\s*[,)]",
                        _re.escape(call) + r"\s+resumed>[^,]+, (\d+)\s*[,)]",
                    ]
                for line in open(args.strace, errors="replace"):
                    for pat in pats:
                        m = _re.search(pat, line)
                        if m:
                            hist[int(m.group(1))] += 1
                            break
                print(f"{call} size histogram:")
                for size, n in hist.most_common(15):
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
             "-e", "cpu-clock" if args.kernel else "cpu-clock:u", "-o", data, *mode,
             "--", "sleep", str(seconds + 1)],
            stderr=open(data + ".log", "w"), stdout=subprocess.DEVNULL)
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
        # --no-children for the flat view (inherited samples drown the callee
        # one is looking for); with --graph the children are the point.
        report = ["perf", "report", "-i", data, "--stdio"]
        if not args.graph:
            report += ["--no-children", "-g", "none"]
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
        import shutil
        shutil.copy(data, keep)


if __name__ == "__main__":
    main()
