#!/usr/bin/env python3
"""Results table from a proto.py run: tachyon-core against sing-box core.

One row per protocol. Each throughput cell carries the percentage one side is
faster by, memory is the peak RSS of the proxy processes, `conns` is how many
simultaneous connections the throughput test opened (1 and 8).

    python scripts/bench/compare.py --in target/bench/proto-20261006-000507.json
    python scripts/bench/compare.py --in result.json --out compare.md
"""
import argparse
import json


def get(row, key):
    return (row or {}).get(key)


def tput(row, streams):
    return get(row, f"tput_{streams}") or {}


def gbit(row, streams):
    return tput(row, streams).get("gbit_s")


def cpu(row, streams):
    return tput(row, streams).get("cpu_s_per_gib")


def faster(ours, theirs):
    if not ours or not theirs:
        return "-"
    return f"{(ours / theirs - 1) * 100:+.0f}%"


def pair(a, b, fmt="{:.2f}"):
    fa = fmt.format(a) if a is not None else "-"
    fb = fmt.format(b) if b is not None else "-"
    return f"{fa} / {fb}"


def tput_cell(ours, theirs, streams):
    o, r = gbit(ours, streams), gbit(theirs, streams)
    if get(ours, "status") not in (None, "OK"):
        return f"**{get(ours, 'status')}**"
    if o is None or r is None:
        return "-"
    return f"{o:.1f} / {r:.1f}"


def rss_sum(row, client_only=False):
    c = get(row, "client_rss_mib")
    s = None if client_only else get(row, "server_rss_mib")
    parts = [f"{x:.1f}" for x in (c, s) if x is not None]
    return "+".join(parts) if parts else "-"


def status_cell(row):
    st = get(row, "status")
    return "-" if row is None else (st if st not in (None, "OK") else "OK")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="src", required=True)
    ap.add_argument("--out", default="", help="write markdown here, default stdout")
    args = ap.parse_args()

    d = json.load(open(args.src, encoding="utf-8"))
    rows = d["results"]
    by = {(r["case"], r.get("part"), r["client"], r["server"]): r for r in rows}
    cases = list(dict.fromkeys(r["case"] for r in rows))

    lines = []
    lines.append(
        f"tachyon-core vs sing-box (`{d.get('ref', 'sing-box')}`), "
        f"{d.get('runs', '?')} runs x {d.get('seconds', '?')}s, "
        f"p50 rounds {d.get('rounds', '?')}; host: {d.get('cpu', '?')} "
        f"({d.get('cores', '?')} cores), client cpus {d.get('client_cpus', '?')}, "
        f"server cpus {d.get('server_cpus', '?')}."
    )
    lines.append("")
    lines.append(
        "Cells: `tachyon / sing-box`. Faster column: `+` = tachyon-core is faster, "
        "`-` = sing-box is. RSS is peak VmHWM of the proxy side(s) named in the "
        "header, in MiB. Connect is median time to a first echoed byte."
    )
    lines.append("")

    for part, title, note in (
        (
            "A",
            "Part A: both sides are the core under test (tachyon client+server vs sing-box client+server)",
            "",
        ),
        (
            "B",
            "Part B: one sing-box server for everyone, the tachyon client against the sing-box client",
            "",
        ),
    ):
        part_cases = [
            c
            for c in cases
            if any(k[1] == part for k in by if k[0] == c)
        ]
        if not part_cases:
            continue
        lines.append(f"### {title}")
        lines.append("")
        lines.append(
            "| protocol | faster (1 / 8 conns) | Gbit/s, 1 conn (t / sb) | "
            "Gbit/s, 8 conns (t / sb) | CPU s/GiB, 8 conns (t / sb) | "
            f"peak RSS MiB, {'client+server' if part == 'A' else 'client'} (t / sb) | "
            "connect ms (t / sb) | interop |"
        )
        lines.append("|---|---|---|---|---|---|---|---|")
        for c in part_cases:
            if part == "A":
                ours = by.get((c, "A", "tachyon", "tachyon"))
                theirs = by.get((c, "A", "ref", "ref"))
                interop = (
                    f"{status_cell(by.get((c, 'A', 'tachyon', 'ref')))} / "
                    f"{status_cell(by.get((c, 'A', 'ref', 'tachyon')))}"
                )
            else:
                ours = by.get((c, "B", "tachyon", "ref"))
                theirs = by.get((c, "B", "ref", "ref"))
                interop = "-"
            if ours is None and theirs is None:
                continue
            f1 = faster(gbit(ours, 1), gbit(theirs, 1))
            f8 = faster(gbit(ours, 8), gbit(theirs, 8))
            lines.append(
                "| {c} | **{f1} / {f8}** | {t1} | {t8} | {cpu} | {rss} | {conn} | {it} |".format(
                    c=c,
                    f1=f1,
                    f8=f8,
                    t1=tput_cell(ours, theirs, 1),
                    t8=tput_cell(ours, theirs, 8),
                    cpu=pair(cpu(ours, 8), cpu(theirs, 8)),
                    rss=f"{rss_sum(ours, part == 'B')} / {rss_sum(theirs, part == 'B')}",
                    conn=pair(get(ours, "connect_ms"), get(theirs, "connect_ms"), "{:.1f}"),
                    it=interop,
                )
            )
        lines.append("")

    fails = d.get("interop_failures") or []
    losses = d.get("losses") or []
    if losses:
        lines.append("Losses by the bench thresholds:")
        lines += [f"- {x}" for x in losses]
        lines.append("")
    if fails:
        lines.append("Interop failures:")
        lines += [f"- {x}" for x in fails]
        lines.append("")

    text = "\n".join(lines)
    if args.out:
        open(args.out, "w", encoding="utf-8").write(text + "\n")
    else:
        print(text)


if __name__ == "__main__":
    main()
