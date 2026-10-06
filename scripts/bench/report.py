"""One page of every proto.py run in a directory: for each protocol cell the
freshest measurement any run produced, so a narrow `-Only` rerun replaces only
its own rows and the rest of the table stays on the last full pass.

Part A is both sides of the pair being the core under test; Part B is one
sing-box server for everyone, so only the clients differ. Every metric group
carries the two numbers and the percentage between them -- `+` always means
tachyon-core is the better side. RSS is peak VmHWM of the proxy side named in
the group header, the throughput columns say how many connections were open.

Modes:
  --in FILE              one run, exactly what it measured;
  --all DIR [--live OUT] the merged view, the run proto.py is currently
                         rewriting forced to the top and marked live.
"""

import argparse
import glob
import html
import json
import os

MIN_SPEED = 0.90
MAX_COST = 1.10

LOSS, WIN, TIE = "loss", "win", "tie"

WHO = {"tachyon": "tachyon-core", "ref": "sing-box"}
REF_NAME = "sing-box"
OUR_NAME = "tachyon-core"


def load(path):
    with open(path, encoding="utf-8") as f:
        run = json.load(f)
    cells = {}
    for row in run["results"]:
        cells.setdefault((row["case"], row["part"]), []).append(row)
    return run, cells


def ours(theirs):
    """The row that is us, and the row that is the reference, same comparison."""
    a = next((r for r in theirs if r["client"] == "tachyon"), None)
    b = next((r for r in theirs if r["client"] == "ref" and r["server"] == "ref"), None)
    return a, b


def cross(theirs, client, server):
    return next(
        (r for r in theirs if r["client"] == client and r["server"] == server), None
    )


def num(row, group, field):
    if not row or not row.get(group):
        return None
    return row[group].get(field)


def rss(row, client_only):
    if not row:
        return None
    parts = [row.get("client_rss_mib")]
    if not client_only:
        parts.append(row.get("server_rss_mib"))
    parts = [p for p in parts if p is not None]
    return sum(parts) if parts else None


def factor(me, them, lower_is_better):
    """Two numbers -> (ratio where above one means ours is better, or None)."""
    if me is None or them is None:
        return None
    if lower_is_better:
        return them / me if me else None
    return me / them if them else None


def cls_of(f, strict, lower):
    if f is None:
        return "none"
    if strict:
        return TIE if abs(f - 1.0) < 1e-9 else (WIN if f > 1.0 else LOSS)
    if lower:
        return LOSS if f < 1.0 / MAX_COST else (WIN if f > 1.0 else TIE)
    return LOSS if f < MIN_SPEED else (WIN if f > 1.0 else TIE)


def pct(f):
    if f is None:
        return "—"
    return f"{(f - 1.0) * 100:+.0f}%"


def cell(value, fmt, cls=""):
    if value is None:
        return '<td class="none">—</td>'
    inner = fmt.format(value)
    return f'<td class="{cls}">{inner}</td>' if cls else f"<td>{inner}</td>"


def head(title, live=False):
    # while the bench is still running, the tab re-reads itself: proto.py
    # rewrites this file after every cell
    refresh = '<meta http-equiv="refresh" content="10">' if live else ""
    return f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">{refresh}
<title>{html.escape(title)}</title>
<style>
 body {{ font: 15px/1.45 system-ui, sans-serif; margin: 24px; color: #1c1c1e; }}
 h1 {{ font-size: 21px; margin: 0 0 4px; }}
 h2 {{ font-size: 16px; margin: 26px 0 8px; }}
 h3 {{ font-size: 15px; margin: 20px 0 8px; }}
 p.sub {{ color: #55555c; margin: 0 0 14px; }}
 p.totals {{ font-size: 16px; margin: 0 0 14px; }}
 .scroll {{ overflow-x: auto; }}
 table {{ border-collapse: collapse; font-size: 13px; }}
 th, td {{ border: 1px solid #d5d5da; padding: 4px 9px; text-align: right;
           white-space: nowrap; font-variant-numeric: tabular-nums; }}
 th {{ background: #f4f4f6; text-align: center; }}
 th.grp {{ background: #e9e9ee; }}
 td.name, th.name {{ text-align: left; }}
 td.pct {{ font-weight: 600; }}
 .win {{ background: #e4f4e4; }}
 .loss {{ background: #fbe4e4; }}
 .tie {{ background: #f6f6f8; }}
 .none {{ color: #8a8a90; }}
 .badge {{ font-size: 11px; padding: 1px 6px; border-radius: 8px;
            background: #fbe4e4; color: #8d2020; margin-left: 6px; }}
 .badge.live {{ background: #e4f4e4; color: #1d6b1d; }}
 .note {{ font-weight: 400; color: #55555c; }}
</style></head><body>
"""


def progress_line(run):
    progress = run.get("progress") or {}
    done, total = progress.get("done"), progress.get("total")
    if not total:
        return "", False
    if done < total:
        cur = progress.get("current")
        tail = f" — сейчас <b>{html.escape(str(cur))}</b>" if cur else ""
        return (
            f'<p class="totals">прогресс: {done} из {total} клеток{tail} — '
            "отчёт обновляется сам, пока бенч идёт</p>",
            True,
        )
    return (
        f'<p class="totals">прогресс: {done} из {total} клеток — бенч закончен</p>',
        False,
    )


def metric_groups(part):
    """(title, how-to-read) per metric, in table order."""
    rss_title = (
        "Пиковая память (клиент+сервер), MiB"
        if part == "A"
        else "Пиковая память клиента, MiB"
    )
    return [
        ("1 соединение, Гбит/с", "tput_1", "gbit_s", "{:.2f}", False),
        ("CPU на ГиБ при 1 соединении, с", "tput_1", "cpu_s_per_gib", "{:.2f}", True),
        ("8 соединений, Гбит/с", "tput_8", "gbit_s", "{:.2f}", False),
        ("CPU на ГиБ при 8 соединениях, с", "tput_8", "cpu_s_per_gib", "{:.2f}", True),
        ("Задержка p50, мкс", None, "p50_us", "{:.0f}", True),
        ("Подключение, мс", None, "connect_ms", "{:.1f}", True),
        (rss_title, "rss", None, "{:.1f}", True),
    ]


def values(a, b, part, group_key, field):
    if group_key == "rss":
        return rss(a, part == "B"), rss(b, part == "B")
    if group_key is None:
        return (a or {}).get(field), (b or {}).get(field)
    return num(a, group_key, field), num(b, group_key, field)


def table(rows_by_case, part, strict):
    client_only = part == "B"
    groups = metric_groups(part)
    with_interop = part == "A"

    header_cells = ['<th class="name" rowspan="2">Протокол</th>']
    header_cells += [f'<th class="grp" colspan="3">{html.escape(g[0])}</th>' for g in groups]
    if with_interop:
        header_cells.append('<th class="grp" rowspan="2">Интероп<br><span class="note">T→ref / ref→T</span></th>')
    header = "<tr>" + "".join(header_cells) + "</tr><tr>"
    for _ in groups:
        header += f"<th>{OUR_NAME}</th><th>{REF_NAME}</th><th>на сколько % лучше</th>"
    header += "</tr>"

    stats = {LOSS: 0, WIN: 0, TIE: 0}
    body = []
    for case, rows in rows_by_case:
        a, b = ours(rows)
        if not a or not b:
            continue
        a_ok = (a.get("status") or "OK") == "OK"
        b_ok = (b.get("status") or "OK") == "OK"
        both_ok = a_ok and b_ok
        classes = []
        out = []
        for group_key, field, fmt, lower, *_rest in (
            (g[1], g[2], g[3], g[4], g[0]) for g in groups
        ):
            if not both_ok:
                # one side failed: there is nothing to compare, same as proto.py
                out += [
                    '<td class="none">—</td>',
                    '<td class="none">—</td>',
                    '<td class="pct none">—</td>',
                ]
                classes.append("none")
                continue
            me, them = values(a, b, part, group_key, field)
            f = factor(me, them, lower)
            if field == "connect_ms" and not strict and f is not None:
                # the bench forgives connect up to 1.5x + 2 ms
                cls = LOSS if me > them * 1.5 + 2.0 else (WIN if f > 1.0 else TIE)
            else:
                cls = cls_of(f, strict, lower)
            classes.append(cls)
            out += [
                cell(me, fmt),
                cell(them, fmt),
                f'<td class="pct {cls}">{pct(f)}</td>',
            ]

        badge = ""
        if not a_ok:
            badge += f'<span class="badge">{html.escape(str(a.get("status")))}</span>'
        if not b_ok:
            badge += f'<span class="badge">ref {html.escape(str(b.get("status")))}</span>'

        if LOSS in classes:
            stats[LOSS] += 1
        elif WIN in classes:
            stats[WIN] += 1
        else:
            stats[TIE] += 1

        interop = ""
        if with_interop:
            states = []
            for client, server in (("tachyon", "ref"), ("ref", "tachyon")):
                r = cross(rows, client, server)
                st = (r or {}).get("status", "—")
                states.append("OK" if st in (None, "OK") else str(st))
            cls = "win" if all(s == "OK" for s in states) else "loss"
            interop = f'<td class="mid {cls}">{" / ".join(states)}</td>'

        body.append(
            f'<tr><td class="name">{html.escape(case)}{badge}</td>' + "".join(out) + interop + "</tr>"
        )

    return (
        f"<table>{header}" + "".join(body) + "</table>",
        stats,
    )


PART_META = {
    "A": (
        "Обе стороны — под тестом: tachyon-core (клиент и сервер) "
        "против sing-box (клиент и сервер)"
    ),
    "B": (
        "Один сервер sing-box с обеих сторон: клиент tachyon-core "
        "против клиента sing-box"
    ),
}


def tables_block(cells, strict):
    """The two part tables plus totals, from merged cells."""
    seen = []
    for (case, part), rows in cells.items():
        a, b = ours(rows)
        if a and b:
            seen.append((case, part))
    seen.sort()

    totals = {LOSS: 0, WIN: 0, TIE: 0}
    out = []
    for part in ("A", "B"):
        part_cases = [(c, cells[(c, p)]) for (c, p) in seen if p == part]
        if not part_cases:
            continue
        table_html, stats = table(part_cases, part, strict)
        for k in totals:
            totals[k] += stats[k]
        out.append(f"<h2>{html.escape(PART_META[part])}</h2>")
        out.append(f'<div class="scroll">{table_html}</div>')

    skipped = sorted(
        {row["case"] for rows in cells.values() for row in rows if row["status"] != "OK"}
    )
    if skipped:
        out.append(
            '<p class="sub">Без данных или с отказом: '
            + ", ".join(html.escape(s) for s in skipped)
            + "</p>"
        )

    totals_html = (
        f'<p class="totals">измерено {len(seen)}, '
        f"побед tachyon-core: {totals[WIN]}, побед sing-box: {totals[LOSS]}, "
        f"паритет: {totals[TIE]}</p>"
    )
    return "".join(out), totals_html


def meta_line(run, strict, extra=""):
    return (
        f'<p class="sub">эталон {html.escape(run.get("ref", REF_NAME))}, '
        f'{run.get("runs")} прогона по {run.get("seconds")} с, '
        f'клиент на ядрах {html.escape(str(run.get("client_cpus")))}, '
        f'сервер на {html.escape(str(run.get("server_cpus")))}, '
        f'задержка — медиана {run.get("rounds")} коннектов подряд, '
        f'ядро {html.escape(str(run.get("kernel")))}. '
        + (
            "Победа засчитывается только при строгом равенстве: не хуже на любую долю."
            if strict
            else f"Порог: скорость не ниже {int(MIN_SPEED * 100)}% эталона, "
            f"CPU, задержка и память не выше {int(MAX_COST * 100)}%, "
            f"подключение — не выше 1.5x эталона + 2 мс."
        )
        + " Колонка «на сколько % лучше»: плюс — tachyon-core лучше на столько процентов."
        + (f" {extra}" if extra else "")
        + "</p>"
    )


def build(run, cells, strict, note=""):
    """A single run, verbatim (--in)."""
    progress_html, _ = progress_line(run)
    body, totals_html = tables_block(cells, strict)
    return (
        head(f"{OUR_NAME} против {REF_NAME}")
        + f"<h1>{OUR_NAME} против {REF_NAME}</h1>"
        + progress_html
        + meta_line(run, strict)
        + totals_html
        + body
        + (f'<p class="sub">{html.escape(note)}</p>' if note else "")
        + "</body></html>"
    )


def collect(dirpath, live_path=None):
    """[(path, run, cells)] newest first with the live run forced to the top.
    Only dated runs count, and a json this reader cannot parse is skipped --
    one broken run must not blank the page."""
    live = os.path.abspath(live_path) if live_path else ""
    paths = sorted(glob.glob(os.path.join(dirpath, "proto-2*.json")), reverse=True)
    entries = []
    for p in paths:
        if os.path.abspath(p) == live:
            continue
        try:
            run, cells = load(p)
        except Exception:
            continue
        if run.get("results"):
            entries.append((p, run, cells))
    if live and os.path.exists(live_path):
        try:
            run, cells = load(live_path)
            if run.get("results"):
                entries.insert(0, (live_path, run, cells))
        except Exception:
            pass
    return entries


def merge_cells(entries):
    """Freshest row per (case, part, client, server): entries are newest first,
    so the first writer of a role wins and later runs only fill the gaps."""
    cells = {}
    for _path, _run, rcells in entries:
        for key, rows in rcells.items():
            dst = cells.setdefault(key, [])
            have = {(r.get("client"), r.get("server")) for r in dst}
            for r in rows:
                role = (r.get("client"), r.get("server"))
                if role not in have:
                    have.add(role)
                    dst.append(r)
    return cells


def build_merged(entries, live_path, strict, note=""):
    """Every run of the directory in one table: the freshest measurement per
    cell, the live run's rows replacing the old ones as it progresses."""
    cells = merge_cells(entries)
    body, totals_html = tables_block(cells, strict)

    progress_html = ""
    running = False
    if live_path and entries and os.path.abspath(entries[0][0]) == os.path.abspath(live_path):
        progress_html, running = progress_line(entries[0][1])

    extra = ""
    if len(entries) > 1:
        extra = f"Свежайшие клетки собраны из {len(entries)} прогонов этого каталога."
    return (
        head(f"{OUR_NAME} против {REF_NAME}", live=running)
        + f"<h1>{OUR_NAME} против {REF_NAME}</h1>"
        + progress_html
        + meta_line(entries[0][1], strict, extra)
        + totals_html
        + body
        + (f'<p class="sub">{html.escape(note)}</p>' if note else "")
        + "</body></html>"
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="src", default="final.json")
    ap.add_argument("--all", dest="all_dir", default="",
                    help="directory of proto-*.json runs, merged freshest-wins")
    ap.add_argument("--live", default="",
                    help="the run proto.py rewrites between cells; merged first")
    ap.add_argument("--out", default="report.html")
    ap.add_argument(
        "--strict",
        action="store_true",
        help="a win counts only above 1.00x on speed and below 1.00x on cost",
    )
    ap.add_argument(
        "--note",
        default="",
        help="a plain-text paragraph appended after the tables",
    )
    args = ap.parse_args()
    if args.all_dir:
        entries = collect(args.all_dir, args.live or None)
        if not entries:
            raise SystemExit(f"no proto-2*.json runs in {args.all_dir}")
        out = build_merged(entries, args.live or None, args.strict, args.note)
    else:
        run, cells = load(args.src)
        out = build(run, cells, args.strict, args.note)
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        f.write(out)


if __name__ == "__main__":
    main()
