"""One page of every proto.py run in a directory: for each protocol cell the
freshest measurement any run produced, so a narrow `-Only` rerun replaces only
its own rows and the rest of the page stays on the last full pass.

The table is a classic comparison grid: one row per protocol, every metric a
group of three columns -- tachyon-core, sing-box and how many percent we are
better -- with the percentage cell tinted green or red and a verdict pill
closing the row. The protocol name column and the header rows are sticky, so
the wide grid stays readable while it scrolls sideways and down in its own
pane.

Runs whose filename ends in `-router.json` form their own host tab (десктоп /
роутер) so a router snapshot never overwrites desktop cells; a single host
renders without tabs.

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
import time

MIN_SPEED = 0.90
MAX_COST = 1.10

LOSS, WIN, TIE = "loss", "win", "tie"
VERDICT_RU = {WIN: "победа", LOSS: "провал", TIE: "паритет"}

OUR_NAME = "tachyon-core"
REF_NAME = "sing-box"

HOST_RU = {"desktop": "десктоп", "router": "роутер"}


def host_of(path):
    return "router" if os.path.basename(path).endswith("-router.json") else "desktop"


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


def fmt_val(v, spec):
    return "—" if v is None else spec.format(v)


def progress_line(run):
    progress = run.get("progress") or {}
    done, total = progress.get("done"), progress.get("total")
    if not total:
        return "", False
    if done < total:
        cur = progress.get("current")
        tail = f" — сейчас <b>{html.escape(str(cur))}</b>" if cur else ""
        return (
            f'<p class="progress">прогресс: {done} из {total} клеток{tail} — '
            "отчёт обновляется сам, пока бенч идёт</p>",
            True,
        )
    return (
        f'<p class="progress done">прогресс: {done} из {total} клеток — бенч закончен</p>',
        False,
    )


def snapshot_line(run, path):
    progress = run.get("progress") or {}
    done, total = progress.get("done"), progress.get("total")
    if not total:
        return ""
    ts = time.strftime("%H:%M", time.localtime(os.path.getmtime(path)))
    return (
        f'<p class="progress">снимок на {ts}: {done} из {total} клеток — '
        "роутер ещё меряет, таблица обновится при следующей выгрузке</p>"
    )


# ------------------------------------------------------------------ rendering
def groups_of(part, bulk_gib):
    """(title, group_key, field, fmt, lower_is_better) per metric group of the
    comparison grid, in the order the columns appear."""
    rss_title = (
        "Пиковая память (клиент+сервер), MiB"
        if part == "A"
        else "Пиковая память клиента, MiB"
    )
    bg = f"{bulk_gib:g}" if bulk_gib else "2"
    return [
        ("1 соединение, Гбит/с", "tput_1", "gbit_s", "{:.2f}", False),
        ("CPU на ГиБ, 1 соединение, с", "tput_1", "cpu_s_per_gib", "{:.2f}", True),
        ("8 соединений, Гбит/с", "tput_8", "gbit_s", "{:.2f}", False),
        ("CPU на ГиБ, 8 соединения, с", "tput_8", "cpu_s_per_gib", "{:.2f}", True),
        (f"Кусок {bg} ГиБ, 1 поток, Гбит/с", "bulk_1", "gbit_s", "{:.2f}", False),
        (f"Кусок {bg} ГиБ, 8 потоков, Гбит/с", "bulk_8", "gbit_s", "{:.2f}", False),
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


def cell_cls(me, them, f, field, strict, lower):
    if field == "connect_ms" and not strict and f is not None:
        # the bench forgives connect up to 1.5x + 2 ms
        return LOSS if me > them * 1.5 + 2.0 else (WIN if f > 1.0 else TIE)
    return cls_of(f, strict, lower)


def verdict_of(a, b, part, strict, groups):
    """(verdict class, both sides measured) for one protocol row."""
    if a.get("status") != "OK" or b.get("status") != "OK":
        return "none", False
    classes = []
    for _title, gk, field, _spec, lower in groups:
        me, them = values(a, b, part, gk, field)
        f = factor(me, them, lower)
        classes.append(cell_cls(me, them, f, field, strict, lower))
    if LOSS in classes:
        return LOSS, True
    if WIN in classes:
        return WIN, True
    return TIE, True


def name_badges(a, b):
    sts = [
        (prefix, str(row.get("status")))
        for row, prefix in ((a, ""), (b, "ref "))
        if row.get("status") and row.get("status") != "OK"
    ]
    if not sts:
        return ""
    uniq = {s for _, s in sts}
    if len(uniq) == 1:
        return f'<span class="badge">{html.escape(uniq.pop())}</span>'
    return "".join(
        f'<span class="badge">{html.escape(p + s)}</span>' for p, s in sts
    )


def thead_html(groups):
    gcells = "".join(
        f'<th class="grp" colspan="3">{html.escape(t)}</th>' for t, *_ in groups
    )
    subs = "".join(
        "<th>tachyon-core</th><th>sing-box</th><th>на сколько % лучше</th>"
        for _ in groups
    )
    return (
        "<thead><tr>"
        '<th class="name" rowspan="2">Протокол</th>'
        + gcells
        + '<th class="vd" rowspan="2">Итог</th>'
        + "</tr><tr>"
        + subs
        + "</tr></thead>"
    )


def grid_row(case, part, rows, a, b, strict, groups):
    """(main row html, verdict class, both sides measured)."""
    vcls, both_ok = verdict_of(a, b, part, strict, groups)
    if both_ok:
        cells = ""
        for _title, gk, field, spec, lower in groups:
            me, them = values(a, b, part, gk, field)
            f = factor(me, them, lower)
            cls = cell_cls(me, them, f, field, strict, lower)
            cells += (
                f'<td class="num">{fmt_val(me, spec)}</td>'
                f'<td class="num">{fmt_val(them, spec)}</td>'
                f'<td class="pct {cls}">{pct(f)}</td>'
            )
        label = VERDICT_RU[vcls]
    else:
        cells = '<td class="num none">—</td><td class="num none">—</td><td class="pct none">—</td>' * len(groups)
        label = "нет данных"

    k = html.escape(f"{part}:{case}")
    main = (
        f'<tr class="case {vcls}" data-k="{k}">'
        f'<td class="name"><span class="cn">{html.escape(case)}</span>'
        f"{name_badges(a, b)}</td>"
        f"{cells}"
        + f'<td class="vd"><span class="vpill {vcls}">{label}</span></td>'
        "</tr>"
    )
    return main, vcls, both_ok


def part_table(part, cases, cells, strict, bulk_gib, totals):
    """One part's comparison table, columns grouped per metric."""
    groups = groups_of(part, bulk_gib)
    rows_html = []
    for case in cases:
        rows = cells[(case, part)]
        a, b = ours(rows)
        row_html, vcls, both_ok = grid_row(case, part, rows, a, b, strict, groups)
        rows_html.append(row_html)
        if both_ok:
            totals[vcls] += 1
    ncol = 1 + 3 * len(groups) + 1
    return (
        f'<div class="scroll"><table class="grid">{thead_html(groups)}'
        "<tbody>" + "".join(rows_html) + "</tbody></table></div>"
    ), ncol


def totals_html_of(totals):
    measured = sum(totals.values())
    return (
        '<div class="chips">'
        f'<div class="chip"><span>измерено клеток</span><b>{measured}</b></div>'
        f'<div class="chip win"><span>побед {OUR_NAME}</span><b>{totals[WIN]}</b></div>'
        f'<div class="chip loss"><span>побед {REF_NAME}</span><b>{totals[LOSS]}</b></div>'
        f'<div class="chip tie"><span>паритет</span><b>{totals[TIE]}</b></div>'
        "</div>"
    )


def tables_html(cells, strict, bulk_gib):
    """Both parts' tables plus the totals chips."""
    seen = []
    for (case, part), rows in cells.items():
        a, b = ours(rows)
        if a and b:
            seen.append((case, part))
    seen.sort()

    titles = {
        "A": "Обе стороны под тестом: tachyon-core ↔ tachyon-core против sing-box ↔ sing-box",
        "B": "Клиент против клиента: сервер sing-box с обеих сторон",
    }
    out, totals = [], {LOSS: 0, WIN: 0, TIE: 0}
    for part in ("A", "B"):
        cases = [c for (c, p) in seen if p == part]
        if not cases:
            continue
        table, _ncol = part_table(part, cases, cells, strict, bulk_gib, totals)
        out.append(f"<h2>{html.escape(titles[part])}</h2>" + table)
    if not out:
        return "", totals_html_of(totals)
    legend = (
        '<p class="legend">в каждой группе колонок слева направо: результат '
        f"<b>{OUR_NAME}</b>, результат <b>{REF_NAME}</b> и на сколько процентов "
        "мы лучше (зелёный) или хуже (красный).</p>"
    )
    return legend + "".join(out), totals_html_of(totals)


def direct_card(run):
    """The no-proxy ceiling of the harness itself, if the run measured it."""
    d = run.get("direct")
    if not d:
        return ""
    lat = (d.get("latency") or {}).get("p50_us")
    specs = [
        ("Задержка p50 без прокси, мкс", lat, "{:.0f}", None),
        ("1 соединение, Гбит/с", num(d, "tput_1", "gbit_s"), "{:.2f}", None),
        ("8 соединений, Гбит/с", num(d, "tput_8", "gbit_s"), "{:.2f}", None),
        ("Кусок, 1 поток, Гбит/с", num(d, "bulk_1", "gbit_s"), "{:.2f}",
         num(d, "bulk_1", "seconds")),
        ("Кусок, 8 потоков, Гбит/с", num(d, "bulk_8", "gbit_s"), "{:.2f}",
         num(d, "bulk_8", "seconds")),
    ]
    rows = ""
    for title, v, spec, extra in specs:
        if v is None:
            continue
        s = spec.format(v)
        if extra is not None:
            s += f'<i class="sub"> {extra:.1f} с</i>'
        rows += f'<tr><td class="m">{html.escape(title)}</td><td class="num">{s}</td></tr>'
    if not rows:
        return ""
    return (
        '<details class="direct">'
        "<summary><span class=\"arrow\"></span>"
        '<span class="cname">Потолок стенда — без прокси</span>'
        '<span class="note">генератор → sink: если клетка упирается в эти числа, '
        "упирается стенд, а не тестируемая сторона</span></summary>"
        '<table class="dtab"><tbody>' + rows + "</tbody></table>"
        "</details>"
    )


def head(title, live=False):
    # while the bench is still running, the tab re-reads itself: proto.py
    # rewrites this file after every cell
    refresh = '<meta http-equiv="refresh" content="10">' if live else ""
    return f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">{refresh}
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>
 :root {{
  --bg: #eef0f4; --card: #ffffff; --head: #f3f4f8; --grp: #e7e9f0;
  --ink: #1b1c22; --muted: #565a66; --faint: #8b909c;
  --line: #d8dae2; --line2: #e8e9ef;
  --win-bg: #e2f4e4; --win-ink: #166b32;
  --loss-bg: #fbe3e3; --loss-ink: #ad2525;
  --tie-bg: #eef0f4; --tie-ink: #565a66;
  --none-bg: #f1f2f5; --none-ink: #8b909c;
  --accent: #4f46e5; --hover: #f0f3ff;
  --shadow: 0 1px 2px rgba(20,20,45,.05), 0 12px 32px -20px rgba(20,20,45,.35);
  --mono: ui-monospace, "SF Mono", "Cascadia Mono", Menlo, Consolas, monospace;
 }}
 @media (prefers-color-scheme: dark) {{
  :root {{
   --bg: #0d0e12; --card: #17181f; --head: #1f2028; --grp: #262732;
   --ink: #f1f2f7; --muted: #9ea2ae; --faint: #757a87;
   --line: #2c2e39; --line2: #23242e;
   --win-bg: #12301f; --win-ink: #5cd98d;
   --loss-bg: #3a1719; --loss-ink: #ff8187;
   --tie-bg: #23242c; --tie-ink: #9ea2ae;
   --none-bg: #1e1f27; --none-ink: #757a87;
   --accent: #7c74f5; --hover: #1d1f2e;
   --shadow: 0 1px 2px rgba(0,0,0,.45), 0 16px 36px -22px rgba(0,0,0,.8);
  }}
 }}
 * {{ box-sizing: border-box; }}
 body {{
  margin: 0; color: var(--ink); font: 14.5px/1.45 -apple-system, "SF Pro Text",
   "Segoe UI Variable Text", Inter, system-ui, sans-serif;
  background: var(--bg);
 }}
 .page {{ max-width: 1640px; margin: 0 auto; padding: clamp(14px,2.2vw,30px) clamp(10px,2vw,24px) 60px; }}
 h1 {{ font-size: clamp(20px,2.4vw,26px); font-weight: 750; letter-spacing: -.02em;
   margin: 0 0 4px; }}
 p.sub {{ color: var(--muted); font-size: 13px; margin: 0 0 12px; }}
 .tabs {{ display: flex; gap: 8px; margin: 10px 0 0; flex-wrap: wrap; }}
 .tab {{ appearance: none; border: 1px solid var(--line); background: var(--card);
   color: var(--muted); font: 650 13.5px/1 inherit; padding: 9px 15px;
   border-radius: 11px; cursor: pointer; box-shadow: var(--shadow);
   transition: border-color .15s, color .15s, transform .15s; }}
 .tab i {{ font-style: normal; font-weight: 600; opacity: .65; font-size: 12px;
   margin-left: 5px; font-family: var(--mono); }}
 .tab:hover {{ border-color: var(--accent); color: var(--accent); transform: translateY(-1px); }}
 .tab.on {{ background: var(--accent); border-color: transparent; color: #fff; }}
 .tab.on i {{ opacity: .85; }}
 .toolbar {{ display: flex; gap: 8px; margin: 10px 0 2px; flex-wrap: wrap; align-items: center; }}
 .btn {{ appearance: none; border: 1px solid var(--line); background: var(--card);
   color: var(--muted); font: 600 12.5px/1 inherit; padding: 8px 13px;
   border-radius: 10px; cursor: pointer; box-shadow: var(--shadow);
   transition: border-color .15s, color .15s, transform .15s; }}
 .btn:hover {{ border-color: var(--accent); color: var(--accent); transform: translateY(-1px); }}
 .btn.on {{ background: var(--accent); border-color: transparent; color: #fff; }}
 #q {{ appearance: none; border: 1px solid var(--line); background: var(--card);
   color: var(--ink); font: 500 13px/1 inherit; padding: 8px 13px; min-width: 200px;
   border-radius: 10px; box-shadow: var(--shadow); margin-left: auto; outline: none; }}
 #q:focus {{ border-color: var(--accent); }}
 #q::placeholder {{ color: var(--faint); }}
 p.progress {{ background: color-mix(in srgb, var(--accent) 8%, var(--card));
   border: 1px solid color-mix(in srgb, var(--accent) 26%, var(--line));
   color: var(--muted); border-radius: 12px; padding: 10px 14px; margin: 12px 0;
   font-size: 13.5px; }}
 p.progress b {{ color: var(--ink); }}
 p.progress.done {{ background: color-mix(in srgb, var(--win-ink) 7%, var(--card));
   border-color: color-mix(in srgb, var(--win-ink) 25%, var(--line)); }}
 .chips {{ display: flex; gap: 10px; margin: 12px 0; flex-wrap: wrap; }}
 .chip {{ display: flex; align-items: center; gap: 12px; background: var(--card);
   border: 1px solid var(--line); border-radius: 12px; padding: 10px 16px;
   box-shadow: var(--shadow); }}
 .chip span {{ color: var(--muted); font-size: 12.5px; font-weight: 600; }}
 .chip b {{ font-size: 21px; font-variant-numeric: tabular-nums; letter-spacing: -.02em; }}
 .chip.win b {{ color: var(--win-ink); }}
 .chip.loss b {{ color: var(--loss-ink); }}
 .chip.tie b {{ color: var(--tie-ink); }}
 section.host {{ margin-top: 4px; }}
 h2 {{ font-size: 15.5px; font-weight: 750; letter-spacing: -.01em;
   margin: 22px 0 8px; }}
 .legend {{ color: var(--muted); font-size: 12.5px; line-height: 1.55;
   margin: 10px 0 6px; }}
 .legend b {{ color: var(--ink); font-weight: 700; }}
 .scroll {{ overflow: auto; background: var(--card); border: 1px solid var(--line);
   border-radius: 14px; box-shadow: var(--shadow);
   max-height: calc(100vh - 130px); }}
 table.grid {{ border-collapse: separate; border-spacing: 0;
   width: max-content; min-width: 100%; font-size: 13px;
   font-variant-numeric: tabular-nums; }}
 .grid th, .grid td {{ border-right: 1px solid var(--line);
   border-bottom: 1px solid var(--line); padding: 5px 9px; white-space: nowrap; }}
 .grid tr:last-child td {{ border-bottom: none; }}
 .grid th:last-child, .grid td:last-child {{ border-right: none; }}
 .grid thead th {{ position: sticky; z-index: 5; background: var(--head);
   color: var(--muted); }}
 .grid thead tr:first-child th {{ top: 0; height: 34px; }}
 .grid thead tr:nth-child(2) th {{ top: 34px; }}
 .grid th.grp {{ font-size: 12px; font-weight: 750; color: var(--ink);
   text-align: center; background: var(--grp); }}
 .grid thead tr:nth-child(2) th {{ font-size: 11px; font-weight: 650;
   text-transform: uppercase; letter-spacing: .04em; text-align: center;
   color: var(--faint); height: 26px; }}
 .grid th.name, .grid td.name {{ position: sticky; left: 0; text-align: left;
   min-width: 210px; }}
 .grid thead th.name {{ z-index: 7; background: var(--grp); color: var(--ink); }}
 .grid td.name {{ z-index: 3; background: var(--card);
   box-shadow: 6px 0 6px -6px rgba(15,15,40,.3); }}
 .cn {{ font-weight: 680; font-size: 13.5px; letter-spacing: -.01em;
   font-family: var(--mono); }}
 .grid td.num {{ text-align: right; font-weight: 550; color: var(--ink); }}
 .grid td.num.none {{ color: var(--none-ink); font-weight: 500; }}
 .grid td.pct {{ text-align: center; font-weight: 700; min-width: 74px; }}
 .grid td.pct.win {{ background: var(--win-bg); color: var(--win-ink); }}
 .grid td.pct.loss {{ background: var(--loss-bg); color: var(--loss-ink); }}
 .grid td.pct.tie {{ background: var(--tie-bg); color: var(--tie-ink); }}
 .grid td.pct.none {{ background: var(--none-bg); color: var(--none-ink); }}
 .grid td.vd {{ text-align: center; }}
 .grid thead th.vd {{ color: var(--ink); font-size: 12px; }}
 tbody tr.case:hover td.num {{ background: var(--hover); }}
 tbody tr.case:hover td.name {{ background: var(--hover); }}
 tr.case.loss td.name {{ box-shadow: inset 3px 0 0 var(--loss-ink),
   6px 0 6px -6px rgba(15,15,40,.3); }}
 .badge {{ font-size: 10.5px; padding: 2px 7px; border-radius: 999px;
   font-weight: 700; background: var(--loss-bg); color: var(--loss-ink);
   margin-left: 7px; vertical-align: 1px; }}
 .vpill {{ font-size: 11.5px; font-weight: 700; padding: 3px 9px;
   border-radius: 999px; white-space: nowrap; }}
 .vpill.win {{ background: var(--win-bg); color: var(--win-ink); }}
 .vpill.loss {{ background: var(--loss-bg); color: var(--loss-ink); }}
 .vpill.tie {{ background: var(--tie-bg); color: var(--tie-ink); }}
 .vpill.none {{ background: var(--none-bg); color: var(--none-ink); }}
 body.losses-only tr.case:not(.loss) {{ display: none; }}
 details.direct {{ background: var(--card); border: 1px solid var(--line);
   border-left: 3px solid var(--accent); border-radius: 12px;
   box-shadow: var(--shadow); margin: 12px 0; overflow: hidden; }}
 details.direct summary {{ list-style: none; display: flex; align-items: center;
   gap: 10px; padding: 11px 15px; cursor: pointer; user-select: none;
   flex-wrap: wrap; }}
 details.direct summary::-webkit-details-marker {{ display: none; }}
 details.direct[open] > summary .arrow {{ transform: rotate(90deg); }}
 .arrow {{ display: inline-block; width: 0; height: 0;
   border: 5px solid transparent; border-left: 7px solid var(--faint);
   transition: transform .18s; vertical-align: middle; }}
 .cname {{ font-weight: 700; font-size: 14px; }}
 .note {{ color: var(--muted); font-size: 12px; font-weight: 500; }}
 table.dtab {{ width: 100%; border-collapse: collapse; font-size: 13px;
   border-top: 1px solid var(--line); }}
 .dtab td {{ padding: 7px 15px; border-bottom: 1px solid var(--line2);
   font-variant-numeric: tabular-nums; }}
 .dtab tr:last-child td {{ border-bottom: none; }}
 .dtab td.m {{ color: var(--muted); }}
 .dtab td.num {{ text-align: right; font-weight: 650; font-family: var(--mono); }}
 .sub {{ font-style: normal; color: var(--faint); font-weight: 500; font-size: 11.5px; }}
 @media (max-width: 760px) {{
  .grid th, .grid td {{ padding: 5px 7px; }}
  .grid td.pct {{ min-width: 62px; }}
  .grid th.name, .grid td.name {{ min-width: 150px; }}
  #q {{ min-width: 140px; flex: 1; margin-left: 0; }}
 }}
</style></head><body>
"""


def toolbar():
    return (
        '<div class="toolbar">'
        '<button class="btn" id="lossBtn" onclick="toggleLosses()">только провалы</button>'
        '<input id="q" placeholder="фильтр: имя протокола…" '
        'autocomplete="off" spellcheck="false">'
        "</div>"
    )


def footer_js():
    return """
<script>
 const KEY = "tachyon-report-v1";
 let state = { losses: false, host: "", q: "" };
 try { state = Object.assign(state, JSON.parse(localStorage.getItem(KEY) || "{}")); }
 catch (e) {}
 function persist() { try { localStorage.setItem(KEY, JSON.stringify(state)); } catch (e) {} }
 function showHost(h, save) {
  state.host = h;
  document.body.dataset.host = h;
  document.querySelectorAll(".tab").forEach(t =>
   t.classList.toggle("on", t.dataset.h === h));
  document.querySelectorAll("section.host").forEach(s => {
   s.hidden = s.dataset.h !== h;
  });
  if (save !== false) persist();
 }
 function applyQ(save) {
  const q = (document.getElementById("q").value || "").trim().toLowerCase();
  if (save !== false) { state.q = q; persist(); }
  document.querySelectorAll("tr.case").forEach(tr => {
   const hit = !q || (tr.dataset.k || "").toLowerCase().includes(q);
   tr.style.display = hit ? "" : "none";
  });
 }
 function toggleLosses() {
  const on = document.body.classList.toggle("losses-only");
  document.getElementById("lossBtn").classList.toggle("on", on);
  state.losses = on;
  persist();
 }
 document.addEventListener("click", e => {
  const tab = e.target.closest(".tab");
  if (tab) showHost(tab.dataset.h);
 });
 document.getElementById("q").addEventListener("input", () => applyQ(true));
 document.addEventListener("DOMContentLoaded", () => {
  if (state.losses) {
   document.body.classList.add("losses-only");
   document.getElementById("lossBtn").classList.add("on");
  }
  const q = document.getElementById("q");
  if (q) { q.value = state.q || ""; applyQ(false); }
  const hosts = Array.from(document.querySelectorAll("section.host"));
  if (hosts.length) {
   const want = hosts.some(s => s.dataset.h === state.host)
    ? state.host : hosts[0].dataset.h;
   showHost(want, false);
  }
 });
</script>
</body></html>
"""


def meta_line(run, strict, extra=""):
    bulk = run.get("bulk_gib")
    bulk_txt = f", кусок {bulk:g} ГиБ" if bulk else ""
    return (
        f'<p class="sub">эталон {html.escape(run.get("ref", REF_NAME))}, '
        f'{run.get("runs")} прогона по {run.get("seconds")} с, '
        f"кусок-замер{bulk_txt}, "
        f'клиент на ядрах {html.escape(str(run.get("client_cpus")))}, '
        f'сервер на {html.escape(str(run.get("server_cpus")))}, '
        f'задержка — медиана {run.get("rounds")} коннектов подряд, '
        f'ядро {html.escape(str(run.get("kernel")))}. '
        + (
            "Победа засчитывается только при строгом равенстве: не хуже на любую долю."
            if strict
            else f"Порог: скорость (включая кусок) не ниже {int(MIN_SPEED * 100)}% эталона, "
            f"CPU, задержка и память не выше {int(MAX_COST * 100)}%, "
            f"подключение — не выше 1.5x эталона + 2 мс."
        )
        + " Колонка «на сколько % лучше»: плюс — tachyon-core лучше на столько процентов."
        + (f" {extra}" if extra else "")
        + "</p>"
    )


# ----------------------------------------------------------------- assembling
def collect(dirpath, live_path=None):
    """[(path, run, cells)] newest first with the live run forced to the top.
    Only dated runs count, and a json this reader cannot parse is skipped --
    one broken run must not blank the page. Runs in the `router` subdirectory
    count too; the filename suffix decides the host tab."""
    live = os.path.abspath(live_path) if live_path else ""
    # by mtime, not by name: a hand-named run like proto-20261007-ws.json sorts
    # above every dated one and would freeze the page on its stale cells
    paths = glob.glob(os.path.join(dirpath, "proto-2*.json")) + glob.glob(
        os.path.join(dirpath, "router", "proto-2*.json")
    )
    paths.sort(key=os.path.getmtime, reverse=True)
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


def host_section(host, h_entries, live_path, strict):
    """One tab's worth: progress, totals, ceiling, the tables, the meta line."""
    cells = merge_cells(h_entries)
    run = h_entries[0][1]
    bulk = run.get("bulk_gib")
    tables, totals_html = tables_html(cells, strict, bulk)

    is_live = live_path and os.path.abspath(h_entries[0][0]) == os.path.abspath(
        live_path
    )
    if is_live:
        progress_html, _ = progress_line(run)
    else:
        progress = run.get("progress") or {}
        if progress.get("total") and progress.get("done", 0) < progress["total"]:
            progress_html = snapshot_line(run, h_entries[0][0])
        else:
            progress_html, _ = progress_line(run)

    n_runs = len(h_entries)
    extra = f"Свежайшие клетки собраны из {n_runs} прогонов." if n_runs > 1 else ""
    body = (
        f'<section class="host" data-h="{host}">'
        + progress_html
        + totals_html
        + direct_card(run)
        + tables
        + meta_line(run, strict, extra)
        + "</section>"
    )
    return body


def tabs_html(by_host, by_entries):
    btns = []
    for host in by_host:
        run = by_entries[host][0][1]
        progress = run.get("progress") or {}
        done, total = progress.get("done"), progress.get("total")
        if total and done < total:
            cnt = f"{done}/{total}"
        elif total:
            cnt = f"{total}"
        else:
            cnt = "—"
        btns.append(
            f'<button class="tab" data-h="{host}">{HOST_RU.get(host, host)}'
            f"<i>{cnt}</i></button>"
        )
    return '<div class="tabs">' + "".join(btns) + "</div>"


def render(entries, live_path, strict, note=""):
    by_host, order = {}, []
    for e in entries:
        h = host_of(e[0])
        if h not in by_host:
            by_host[h] = []
            order.append(h)
        by_host[h].append(e)
    order.sort(key=lambda h: ("desktop" != h, h))  # десктоп первым

    running = False
    if live_path and entries and os.path.abspath(entries[0][0]) == os.path.abspath(
        live_path
    ):
        _, running = progress_line(entries[0][1])

    sections = "".join(
        host_section(h, by_host[h], live_path, strict) for h in order
    )
    tabs = tabs_html(order, by_host) if len(order) > 1 else ""
    return (
        head(f"{OUR_NAME} против {REF_NAME}", live=running)
        + '<div class="page">'
        + f"<h1>{OUR_NAME} против {REF_NAME}</h1>"
        + '<p class="sub">свежайшие замеры каждой клетки из всех прогонов каталога; '
        "все метрики на виду — ничего не нужно раскрывать</p>"
        + tabs
        + toolbar()
        + sections
        + (f'<p class="sub">{html.escape(note)}</p>' if note else "")
        + "</div>"
        + footer_js()
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="src", default="final.json")
    ap.add_argument("--all", dest="all_dir", default="",
                    help="directory of proto-2*.json runs, merged freshest-wins; "
                         "runs in its router/ subdirectory form a second host tab")
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
        out = render(entries, args.live or None, args.strict, args.note)
    else:
        run, cells = load(args.src)
        out = render([(args.src, run, cells)], None, args.strict, args.note)
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        f.write(out)


if __name__ == "__main__":
    main()
