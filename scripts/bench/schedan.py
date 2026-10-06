#!/usr/bin/env python3
"""Per-thread off-cpu story from a `perf sched record` file.

    schedan.py /bench/foo.sched [target_pid]

perf script rows carry two id spaces: the row tid/pid is what /proc shows in
the recording namespace, while the event payload pids come from the other one
(a container vs its host). sched_switch rows pair them: row id = prev thread,
payload prev_pid = the same thread in the other space. Everything else --
sched_stat_runtime totals, sleep gaps, wakeup pairs -- is keyed through that
map, so the output speaks in the ids the rest of the bench uses.

Without target_pid the target threads are picked by comm (tachyon-core /
tokio-rt-worker); with it, /proc/<pid>/task is consulted while it is alive.
"""
import collections
import os
import re
import subprocess
import sys

ROW = re.compile(r"^\s*(.+?)\s+(\d+)\s+\[(\d+)\]\s+(\d+\.\d+):\s+(\S+):\s*(.*)$")
SW = re.compile(r"prev_comm=(\S+) prev_pid=(\d+) .*?prev_state=(\S+)\s*==> "
                r"next_comm=(\S+) next_pid=(\d+)")
WK = re.compile(r"comm=(\S+) pid=(\d+) prio=\d+")
RT = re.compile(r"pid=(\d+) runtime=(\d+)")
OURS = {"tachyon-core", "tokio-rt-worker"}


def main():
    data = sys.argv[1]
    target = int(sys.argv[2]) if len(sys.argv) > 2 else None
    out = subprocess.run(["perf", "script", "-i", data],
                         capture_output=True, text=True).stdout
    host2row = {}
    rowcomm = {}
    run = collections.Counter()
    sleeps = collections.defaultdict(list)
    stalls = collections.defaultdict(list)
    out_state = {}
    wakes = collections.Counter()
    in_wakes = collections.defaultdict(collections.Counter)
    for line in out.splitlines():
        m = ROW.match(line)
        if not m:
            continue
        comm, row, cpu, ts, ev, fields = m.groups()
        row, ts = int(row), float(ts)
        ev = ev.rsplit(":", 1)[-1]
        if ev == "sched_switch":
            s = SW.search(fields)
            if not s:
                continue
            pcomm, hp, state, ncomm, hnext = s.groups()
            hp, hnext = int(hp), int(hnext)
            host2row[hp] = row
            rowcomm.setdefault(row, pcomm)
            nr = host2row.get(hnext)
            if nr is not None and nr in out_state:
                t0, st = out_state.pop(nr)
                dur = ts - t0
                (sleeps if st == "S" else stalls)[nr].append(dur)
            out_state[row] = (ts, state)
        elif ev == "sched_waking":
            s = WK.search(fields)
            if not s:
                continue
            _, hp = s.groups()
            wr = host2row.get(int(hp))
            if wr is not None:
                wakes[(rowcomm.get(row, "?"), row, rowcomm.get(wr, "?"), wr)] += 1
                in_wakes[wr][rowcomm.get(row, "?")] += 1
        elif ev == "sched_stat_runtime":
            s = RT.search(fields)
            if s:
                hp, ns = s.groups()
                r = host2row.get(int(hp))
                if r is not None:
                    run[r] += int(ns) / 1e9
    if target is not None and os.path.isdir(f"/proc/{target}/task"):
        ours = {int(t) for t in os.listdir(f"/proc/{target}/task")}
    else:
        ours = {r for r, c in rowcomm.items() if c in OURS}
    print(f"our rows: {sorted(ours)}")
    print(f"{'row':>5} {'comm':<16} {'run_s':>8} {'sleeps':>7} "
          f"{'avg_us':>8} {'p50_us':>8} {'max_us':>9} {'stall_us':>9}")
    for r in sorted(ours | set(run), key=lambda k: -run.get(k, 0)):
        ss = sorted(sleeps.get(r, []))
        n = len(ss)
        avg = sum(ss) / n if n else 0
        p50 = ss[n // 2] if n else 0
        mx = ss[-1] if n else 0
        stall = sum(stalls.get(r, []))
        mark = "*" if r in ours else " "
        print(f"{mark}{r:>4} {rowcomm.get(r, '?'):<16} {run.get(r, 0):>8.3f} {n:>7} "
              f"{avg * 1e6:>8.1f} {p50 * 1e6:>8.1f} {mx * 1e6:>9.1f} "
              f"{stall * 1e6:>9.1f}")
    for r in sorted(ours):
        if in_wakes.get(r):
            top = ", ".join(f"{k}:{v}" for k, v in in_wakes[r].most_common(6))
            print(f"wakes into {r} ({rowcomm.get(r, '?')}): {top}")
    print("--- wakeup pairs touching ours (waker -> wakee)")
    sel = [(k, n) for k, n in wakes.items() if k[1] in ours or k[3] in ours]
    for (wc, wr, tc, tr), n in sorted(sel, key=lambda kv: -kv[1])[:20]:
        mark = "*" if tr in ours else " "
        print(f" {mark} {wc}[{wr}] -> {tc}[{tr}] : {n}")


if __name__ == "__main__":
    main()
