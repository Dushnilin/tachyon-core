#!/usr/bin/env python3
"""Сводная html-таблица ночной нагрузки: load-*.json в одной директории.

    python3 night_report.py target/bench/router --out NIGHT.html
"""
import argparse
import glob
import html
import json
import os

CSS = """
body{font:14px/1.45 system-ui,sans-serif;margin:24px;background:#fafafa;color:#222}
h1{font-size:20px;margin:0 0 4px}
.meta{color:#666;font-size:13px;margin-bottom:14px}
table{border-collapse:collapse;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.12)}
th,td{padding:5px 10px;border-bottom:1px solid #eee;text-align:right;font-variant-numeric:tabular-nums}
th{background:#2b2b2b;color:#eee;font-weight:600;text-align:right}
th:first-child,td:first-child,th:nth-child(2),td:nth-child(2){text-align:left}
tr:nth-child(even){background:#f7f7f7}
.ok{color:#1a7f37;font-weight:600}.died{color:#b45309;font-weight:600}
.fail{color:#b91c1c;font-weight:600}
.sum{margin-top:14px;font-size:13px;color:#444}
"""


def fmt(v, spec="{:.2f}", dash="—"):
    return spec.format(v) if isinstance(v, (int, float)) else dash


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir")
    ap.add_argument("--out", default="NIGHT.html")
    a = ap.parse_args()

    runs = []
    for p in sorted(glob.glob(os.path.join(a.dir, "load-*.json"))):
        if p.endswith("load-summary.json"):
            continue
        with open(p) as f:
            runs.append(json.load(f))
    summary = {}
    sp = os.path.join(a.dir, "load-summary.json")
    if os.path.exists(sp):
        with open(sp) as f:
            summary = json.load(f)
    if not runs:
        raise SystemExit(f"нет load-*.json в {a.dir}")

    rows, gib_up, gib_dn = [], 0.0, 0.0
    for i, r in enumerate(runs, 1):
        st = r.get("status", "?")
        peak = r.get("rss_peak_mib") or {}
        end, start = r.get("rss_end_mib") or {}, r.get("rss_start_mib") or {}
        drift = (lambda k: (end.get(k, 0) or 0) - (start.get(k, 0) or 0)) if end else (lambda k: None)
        tot = r.get("totals_gib") or {}
        gib_up += tot.get("up", 0) or 0
        gib_dn += tot.get("dn", 0) or 0
        rates = r.get("gbit_per_min") or []
        cpu_c = r.get("client_cpu_pct_per_min") or []
        cpu_s = r.get("server_cpu_pct_per_min") or []
        rows.append(f"""<tr><td>{i}</td><td>{html.escape(r['case'])}</td>
<td class="{st.lower()}">{st}</td>
<td>{r.get('conns_opened', '—')}/{r.get('conns_died', 0)}</td>
<td>{fmt(r.get('gbit_avg'))}</td>
<td>{fmt(r.get('gbit_min'))}..{fmt(r.get('gbit_max'))}</td>
<td>{fmt(tot.get('up'))}/{fmt(tot.get('dn'))}</td>
<td>{fmt(peak.get('client'), '{:.0f}')}/{fmt(peak.get('server'), '{:.0f}')}</td>
<td>{fmt(drift('client'), '{:+.1f}')}/{fmt(drift('server'), '{:+.1f}')}</td>
<td>{fmt(sum(cpu_c) / len(cpu_c), '{:.0f}') if cpu_c else '—'}/{fmt(sum(cpu_s) / len(cpu_s), '{:.0f}') if cpu_s else '—'}</td>
<td>{len(rates)}</td></tr>""")

    ok = sum(1 for r in runs if r.get("status") == "OK")
    dev = " · ".join(str(summary[k]) for k in ("cpu", "cores", "mem_mib", "kernel") if k in summary)
    head = (f"{summary.get('started', '?')} — {summary.get('finished', '')} · "
            f"{summary.get('conns', '?')} коннектов · {summary.get('minutes', '?')} мин/протокол"
            if summary else "")
    page = f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<title>Ночная нагрузка tachyon-core</title><style>{CSS}</style></head><body>
<h1>Ночная нагрузка tachyon-core — только tachyon, без сравнения</h1>
<div class="meta">{html.escape(head)}<br>{html.escape(dev)}<br>
половина коннектов заливает, половина качает, трафик без остановки; RSS-дрейф = конец минус старт</div>
<table><tr><th>#</th><th>протокол</th><th>статус</th><th>коннекты<br>открыто/умерло</th>
<th>Гбит/с<br>ср</th><th>Гбит/с<br>мин..макс</th><th>ГиБ<br>up/dn</th>
<th>пик RSS МиБ<br>клиент/сервер</th><th>дрейф RSS МиБ<br>клиент/сервер</th>
<th>CPU %<br>клиент/сервер</th><th>мин</th></tr>
{os.linesep.join(rows)}</table>
<div class="sum">итог: {ok} OK из {len(runs)} · перекачано {gib_up + gib_dn:.0f} ГиБ
(up {gib_up:.0f} / down {gib_dn:.0f})</div>
</body></html>
"""
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(page)
    print(f"{a.out}: {len(runs)} протоколов, {ok} OK")


if __name__ == "__main__":
    main()
