"""One table out of a proto.py run: every protocol, both implementations, and who won.

No tiles, no bars, no ratios written as a bare multiplier with nothing to compare
them against. Every row carries the two numbers the factor was made from.
"""

import argparse
import html
import json

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


def plural(x):
    """Russian count. With decimals it is always "раза" (1,21 раза); without, the
    last digit decides the way it does for any count (5 раз, 21 раз, 2 раза)."""
    if abs(x - round(x)) > 1e-9:
        return "раза"
    n = int(round(x)) % 100
    if 11 <= n <= 14:
        return "раз"
    return "раз" if n % 10 == 1 else ("раза" if 2 <= n % 10 <= 4 else "раз")


def num(row, group, field):
    if not row or not row.get(group):
        return None
    return row[group].get(field)


def factor(me, them, lower_is_better):
    if not me or not them:
        return None, "tie", None
    if lower_is_better:
        f = them / me if me else None
    else:
        f = me / them if them else None
    if not f:
        return None, "tie", None
    # for a cost metric f is ref/ours: above one we are cheaper, so being much
    # above one is a win, not the loss it looks like
    if lower_is_better:
        cls = LOSS if f < 1.0 / MAX_COST else (WIN if f > 1.0 else TIE)
    else:
        cls = LOSS if f < MIN_SPEED else (WIN if f > 1.0 else TIE)
    return f, cls, f


def head(title):
    return f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<title>{html.escape(title)}</title>
<style>
 body {{ font: 15px/1.45 system-ui, sans-serif; margin: 24px; color: #1c1c1e; }}
 h1 {{ font-size: 21px; margin: 0 0 4px; }}
 p.sub {{ color: #55555c; margin: 0 0 18px; }}
 p.totals {{ font-size: 16px; margin: 0 0 18px; }}
 table {{ border-collapse: collapse; font-size: 14px; width: 100%; }}
 th, td {{ border: 1px solid #d5d5da; padding: 5px 8px; text-align: right; }}
 th {{ background: #f4f4f6; text-align: center; }}
 th.grp {{ text-align: center; background: #e9e9ee; }}
 td.name, th.name {{ text-align: left; }}
 td.mid, th.mid {{ text-align: center; }}
 .win {{ background: #e4f4e4; }}
 .loss {{ background: #fbe4e4; }}
 .tie {{ background: #f6f6f8; }}
 .none {{ color: #8a8a90; }}
</style></head><body>
"""


def cell(value, fmt, cls=""):
    if value is None:
        return f'<td class="none {cls}">—</td>'
    return f'<td class="{cls}">{fmt.format(value)}</td>'


def build(run, cells, strict):
    low, high = (1.0, 1.0) if strict else (MIN_SPEED, MAX_COST)
    parts = []
    seen = []
    for (case, part), rows in cells.items():
        a, b = ours(rows)
        if not a or not b:
            continue
        what = (
            f"обе стороны {OUR_NAME}"
            if a["server"] == "tachyon"
            else f"клиент {OUR_NAME} → сервер {REF_NAME}"
        )
        seen.append((case, part, what))
    seen.sort(key=lambda t: (t[0], t[1]))

    wins = losses = ties = 0
    body = []

    def judge(f, lower):
        """One ratio -> (css class, word). `lower` means a smaller number is better."""
        if f is None:
            return "none", ""
        better = f > 1.0
        if strict:
            cls = "tie" if abs(f - 1.0) < 1e-9 else ("win" if better else "loss")
        elif lower:
            # f is ref/ours here too: above one we are cheaper
            cls = LOSS if f < 1.0 / MAX_COST else (WIN if f > 1.0 else TIE)
        else:
            cls = LOSS if f < MIN_SPEED else (WIN if f > 1.0 else TIE)
        return cls, better

    for case, part, what in seen:
        rows = cells[(case, part)]
        a, b = ours(rows)
        classes = []
        out = []

        def pair(me, them, fmt, lower, tail):
            f, _, _ = factor(me, them, lower)
            cls, better = judge(f, lower)
            classes.append(cls)
            # the number belongs to the winner: sing-box being 1.22x faster is
            # "sing-box в 1.22 раза быстрее", not "в 0.82"
            who = OUR_NAME if better else REF_NAME
            mag = f if better else (1.0 / f if f else None)
            return (
                cell(me, fmt),
                cell(them, fmt),
                f'<td class="{cls}">{who} в {mag:.2f} {plural(mag)} {tail}</td>'
                if mag is not None
                else '<td class="none">-</td>',
            )

        for group_key, field, fmt, lower, words in (
            ("tput_1", "gbit_s", "{:.2f}", False, "быстрее"),
            ("tput_8", "gbit_s", "{:.2f}", False, "быстрее"),
            ("tput_8", "cpu_s_per_gib", "{:.2f}", True, "экономнее по CPU"),
            (None, "p50_us", "{:.0f}", True, "ниже задержка"),
        ):
            if group_key is None:
                me = (a or {}).get("p50_us")
                them = (b or {}).get("p50_us")
            else:
                me = num(a, group_key, field)
                them = num(b, group_key, field)
            out += pair(me, them, fmt, lower, words)

        if LOSS in classes:
            losses += 1
        elif WIN in classes:
            wins += 1
        else:
            ties += 1
        body.append(
            f'<tr><td class="name">{html.escape(case)}</td>'
            f'<td class="name"><small>{html.escape(what)}</small></td>'
            + "".join(out)
            + "</tr>"
        )

    groups = [
        ("Скорость, 1 поток, Гбит/с", ""),
        ("Скорость, 8 потоков, Гбит/с", ""),
        ("CPU на ГиБ данных, 8 потоков, с", ""),
        ("Задержка p50, мкс", ""),
    ]
    header = (
        '<tr><th class="name" rowspan="2">Протокол</th>'
        '<th class="name" rowspan="2">Что сравнивается</th>'
        + "".join(
            f'<th class="grp" colspan="3">{g}</th>' for g, _ in groups
        )
        + '</tr>'
        '<tr>'
        + "".join(
            f'<th>{OUR_NAME}</th><th>{REF_NAME}</th><th class="name">кто и во сколько раз</th>'
            for _ in groups
        )
        + "</tr>"
    )

    measured = len(seen)
    skipped = sorted(
        {row["case"] for rows in cells.values() for row in rows if row["status"] != "OK"}
    )
    skip_html = ""
    if skipped:
        skip_html = (
            "<p class=\"sub\">Без данных: "
            + ", ".join(html.escape(s) for s in skipped)
            + "</p>"
        )

    meta = (
        f'<p class="sub">эталон {html.escape(run.get("ref", REF_NAME))}, '
        f'{run.get("runs")} прогона по {run.get("seconds")} с, '
        f'клиент на ядрах {html.escape(str(run.get("client_cpus")))}, '
        f'сервер на {html.escape(str(run.get("server_cpus")))}, '
        f'ядро {html.escape(str(run.get("kernel")))}. '
        + (
            "Победа засчитывается только при строгом равенстве: не хуже на любую долю."
            if strict
            else f"Порог: скорость не ниже {int(MIN_SPEED * 100)}% эталона, "
            f"CPU и задержка не выше {int(MAX_COST * 100)}%."
        )
        + "</p>"
    )

    parts.append(
        head(f"{OUR_NAME} против {REF_NAME}")
        + f"<h1>{OUR_NAME} против {REF_NAME}</h1>"
        + meta
        + f'<p class="totals">измерено {measured}, '
        f"побед tachyon-core: {wins}, побед sing-box: {losses}, паритет: {ties}</p>"
        + f"<table>{header}" + "".join(body) + "</table>"
        + skip_html
        + "</body></html>"
    )
    return "".join(parts)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="src", default="final.json")
    ap.add_argument("--out", default="report.html")
    ap.add_argument(
        "--strict",
        action="store_true",
        help="a win counts only above 1.00x on speed and below 1.00x on cost",
    )
    args = ap.parse_args()
    run, cells = load(args.src)
    open(args.out, "w", encoding="utf-8", newline="\n").write(build(run, cells, args.strict))


if __name__ == "__main__":
    main()