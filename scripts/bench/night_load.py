#!/usr/bin/env python3
"""Ночная нагрузка: только tachyon-core, по очереди каждый протокол матрицы.

На каждый протокол: tachyon-клиент + tachyon-сервер, N коннектов по SOCKS
(половина заливает, половина качает — трафик без остановки), minutes минут.
Между протоколами — 5 минут отдыха роутеру. Раз в минуту: Гбит/с по
направлениям, RSS и CPU обоих ядер, живые коннекты. Итог протокола —
results/load-<имя>.json (готовый файл пропускается, так что
прогон можно перезапускать и он продолжит с места падения), после всех —
results/load-summary.json.

    python3 night_load.py --tachyon ./tachyon-core --minutes 20 --conns 10000
"""
import argparse
import asyncio
import json
import os
import signal
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bench  # noqa: E402
import proto  # noqa: E402

CHUNK = 16384
WRITE_CAP = 32768       # per-conn буфер заливки, дальше drain
OPEN_BATCH = 250
OPEN_TIMEOUT = 60       # медленные QUIC-хендшейки на слабом ядре

# Второе ядро: сервер + синк/реалити-назначение, первое: клиент + генератор.
CLIENT_CPUS, SERVER_CPUS = {0}, {1}
REST_SEC = 300   # отдых роутера между протоколами
PROXY_PORT, SERVER_PORT = proto.PROXY_PORT_BASE + 1, proto.SERVER_PORT_BASE + 1


async def pump_up(w, stats):
    """Заливка: пишем, пока транспорт принимает, иначе drain."""
    buf = b"\x5a" * CHUNK
    try:
        while True:
            w.write(buf)
            stats["up"] += len(buf)
            if w.transport.get_write_buffer_size() >= WRITE_CAP:
                await w.drain()
            else:
                await asyncio.sleep(0)   # не душить цикл на чистой записи
    except (ConnectionError, OSError, asyncio.CancelledError):
        pass


async def pump_down(r, stats):
    """Качка: читаем и отбрасываем, счёт по принятым байтам."""
    try:
        while True:
            data = await r.read(CHUNK)
            if not data:
                return
            stats["dn"] += len(data)
    except (ConnectionError, OSError, asyncio.CancelledError):
        pass


async def open_conns(count, mode):
    conns, failed = [], 0
    for batch in range(0, count, OPEN_BATCH):
        res = await asyncio.gather(
            *(asyncio.wait_for(bench.async_socks_connect(True, mode), OPEN_TIMEOUT)
              for _ in range(min(OPEN_BATCH, count - batch))),
            return_exceptions=True)
        for item in res:
            if isinstance(item, BaseException):
                failed += 1
            else:
                conns.append(item)
        await asyncio.sleep(0.05)
    return conns, failed


def gbit(delta_bytes, seconds):
    return delta_bytes * 8 / seconds / 1e9


async def run_case(case, args, work):
    """Один протокол: поднять оба ядра, раскрыть коннекты, крутить минуты."""
    name = case["name"]
    bench.PROXY_PORT = PROXY_PORT
    res = {"case": name, "conns_target": args.conns, "minutes_planned": args.minutes,
           "status": "OK", "why": ""}
    server = proto.Proc(args.tachyon, proto.server_cfg(case, SERVER_PORT),
                        SERVER_CPUS, work, "server")
    client = proto.Proc(args.tachyon, proto.client_cfg(case, PROXY_PORT, SERVER_PORT),
                        CLIENT_CPUS, work, "client")
    conns, tasks = [], []
    try:
        for who, proc, port in (("server", server, SERVER_PORT), ("client", client, PROXY_PORT)):
            if not proto.wait_port_free(port):
                res.update(status="FAIL", why=f"{who} port {port} still held")
                return res
            ok, msg = proc.check()
            if not ok:
                res.update(status="FAIL", why=f"{who} check: {msg[-200:]}")
                return res
        server.start()
        time.sleep(0.4)
        client.start()
        # wait_listen бросает TimeoutError, его ловит общий except ниже
        bench.wait_listen(PROXY_PORT, timeout=15)
        why = proto.probe()
        if why:
            res.update(status="FAIL",
                       why=f"{why} s:[{server.tail()}] c:[{client.tail()}]")
            return res

        up_n = (args.conns + 1) // 2
        down_conns, failed1 = await open_conns(args.conns - up_n, bench.MODE_SOURCE)
        up_conns, failed2 = await open_conns(up_n, bench.MODE_SINK)
        res.update(conns_opened=len(up_conns) + len(down_conns),
                   conns_failed_open=failed1 + failed2)
        if res["conns_opened"] < min(args.conns, 100):
            res.update(status="FAIL", why=f"only {res['conns_opened']} conns opened")
            return res
        conns = up_conns + down_conns
        stats = {"up": 0, "dn": 0}
        for w, _ in up_conns:
            tasks.append(asyncio.create_task(pump_up(w, stats)))
        for r, _ in down_conns:
            tasks.append(asyncio.create_task(pump_down(r, stats)))

        rss0 = {"client": bench.proc_status(client.p.pid).get("VmRSS", 0),
                "server": bench.proc_status(server.p.pid).get("VmRSS", 0)}
        cpu0 = {"client": sum(bench.cpu_split(client.p.pid)),
                "server": sum(bench.cpu_split(server.p.pid))}
        res.update(rss_start_mib=rss0, gbit_per_min=[], alive_per_min=[],
                   client_cpu_pct_per_min=[], server_cpu_pct_per_min=[])

        prev = {"up": 0, "dn": 0}
        for minute in range(args.minutes):
            await asyncio.sleep(60)
            alive = sum(1 for t in tasks if not t.done())
            cu, cs = bench.cpu_split(client.p.pid), bench.cpu_split(server.p.pid)
            res["gbit_per_min"].append(round(
                gbit(stats["up"] - prev["up"], 60) + gbit(stats["dn"] - prev["dn"], 60), 4))
            res["alive_per_min"].append(alive)
            res["client_cpu_pct_per_min"].append(
                round((sum(cu) - cpu0["client"]) * 100 / 60, 1))
            res["server_cpu_pct_per_min"].append(
                round((sum(cs) - cpu0["server"]) * 100 / 60, 1))
            prev = dict(stats)
            print(f"  [{name}] мин {minute + 1}/{args.minutes}: "
                  f"{res['gbit_per_min'][-1]:.2f} Гбит/с, живых {alive}, "
                  f"RSS c/s {bench.proc_status(client.p.pid).get('VmRSS', 0):.0f}/"
                  f"{bench.proc_status(server.p.pid).get('VmRSS', 0):.0f} МиБ", flush=True)
            # ядро умерло — коннекты повиснут полумёртвыми и alive не сойдёт
            # в ноль; ловим сразу, с хвостом ядра в логе
            for who, proc in (("server", server), ("client", client)):
                if proc.p.poll() is not None:
                    res.update(status="FAIL", why=f"{who} умер на минуте "
                               f"{minute + 1}: {proc.tail()[-300:]}")
                    print(f"  !! {res['why']}", flush=True)
                    break
            if res["status"] != "OK":
                break
            if alive == 0:
                res.update(status="DIED", why=f"все коннекты умерли на минуте {minute + 1}")
                break

        res["totals_gib"] = {"up": round(stats["up"] / 2**30, 2),
                             "dn": round(stats["dn"] / 2**30, 2)}
        rates = res["gbit_per_min"]
        if rates:
            res.update(gbit_avg=round(sum(rates) / len(rates), 3),
                       gbit_min=min(rates), gbit_max=max(rates))
        res["conns_died"] = len(tasks) - sum(1 for t in tasks if not t.done())
        res["rss_end_mib"] = {"client": bench.proc_status(client.p.pid).get("VmRSS", 0),
                              "server": bench.proc_status(server.p.pid).get("VmRSS", 0)}
        res["rss_peak_mib"] = {"client": bench.proc_status(client.p.pid).get("VmHWM", 0),
                               "server": bench.proc_status(server.p.pid).get("VmHWM", 0)}
    except Exception as e:  # noqa: BLE001 - протокол упал, ночь продолжается
        res.update(status="FAIL", why=f"{type(e).__name__}: {e} c:[{client.tail()}]")
    finally:
        for t in tasks:
            t.cancel()
        for _, w in conns:
            try:
                w.close()
            except OSError:
                pass
        client.stop()
        server.stop()
        try:
            await asyncio.sleep(0.5)
        except asyncio.CancelledError:
            pass   # нас рвут по Ctrl+C, порты всё равно освободили stop()
        for port in (PROXY_PORT, SERVER_PORT):
            proto.wait_port_free(port, timeout=5)
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tachyon", required=True)
    ap.add_argument("--ref", default="./sing-box",
                    help="нужен только для generate reality-keypair")
    ap.add_argument("--minutes", type=int, default=20)
    ap.add_argument("--conns", type=int, default=10000)
    ap.add_argument("--only", default="", help="подстроки имён через запятую")
    ap.add_argument("--out-dir", default="results")
    ap.add_argument("--work", default=os.environ.get("PROTO_WORK") or ".")
    args = ap.parse_args()

    # StopAt снимает прогон по SIGTERM — пускаем SystemExit, чтобы finally
    # остановил оба ядра и записал сводку, иначе tachyon остаётся с портами
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(1))

    os.makedirs(args.out_dir, exist_ok=True)
    os.sched_setaffinity(0, CLIENT_CPUS)
    threading.Thread(target=bench.run_sink, args=(SERVER_CPUS,), daemon=True).start()
    if not bench.wait_listen(bench.SINK_PORT):
        print("sink port занят, висит чей-то прогон?", file=sys.stderr)
        sys.exit(1)

    certs = proto.make_certs(args.work)
    reality = proto.make_reality(args.ref)
    if reality:
        threading.Thread(target=proto.run_tls_dest, args=(certs, SERVER_CPUS),
                         daemon=True).start()
        bench.wait_listen(proto.REALITY_DEST_PORT)

    only = [s for s in args.only.split(",") if s]
    cases = [c for c in proto.build_cases(certs, reality)
             if not only or any(s in c["name"] for s in only)]
    started = time.strftime("%Y-%m-%d %H:%M:%S")
    done = []
    # ядра упавшего прошлого прогона (OOM, kill) держат 21101/21201 —
    # без этой уборки первый же протокол упал бы с «server port still held»
    proto.kill_cell_proxies(args.work)
    try:
        for i, case in enumerate(cases, 1):
            out = os.path.join(args.out_dir, f"load-{case['name']}.json")
            if os.path.exists(out):
                print(f"({i}/{len(cases)}) {case['name']}: уже есть, пропуск", flush=True)
                continue
            if done:
                # отдых роутера между протоколами: температура и порты
                print(f"  отдых {REST_SEC // 60} минут", flush=True)
                time.sleep(REST_SEC)
            print(f"({i}/{len(cases)}) {case['name']}: "
                  f"{args.conns} коннектов, {args.minutes} мин", flush=True)
            t0 = time.time()
            res = asyncio.run(run_case(case, args, args.work))
            res["wall_seconds"] = round(time.time() - t0)
            with open(out, "w") as f:
                json.dump(res, f, indent=1)
            done.append(res)
            line = f"  -> {res['status']}"
            if res.get("gbit_avg") is not None:
                line += (f"  {res['gbit_avg']:.2f} Гбит/с "
                         f"(мин {res['gbit_min']:.2f}..{res['gbit_max']:.2f})")
            if res.get("rss_peak_mib"):
                line += (f"  RSS пик c/s {res['rss_peak_mib']['client']:.0f}/"
                         f"{res['rss_peak_mib']['server']:.0f} МиБ")
            if res.get("why"):
                line += f"  {res['why'][:160]}"
            print(line, flush=True)
            time.sleep(10)   # TIME_WAIT и остыть портам
    finally:
        proto.kill_cell_proxies(args.work)
        summary = {
            "started": started, "finished": time.strftime("%Y-%m-%d %H:%M:%S"),
            "conns": args.conns, "minutes": args.minutes,
            "cpu": next((l.split(":")[1].strip() for l in open("/proc/cpuinfo")
                         if l.startswith("model name")), "?"),
            "cores": os.cpu_count(),
            "mem_mib": int(open("/proc/meminfo").readline().split()[1]) // 1024,
            "kernel": os.uname().release,
            "cases": [{"case": r["case"], "status": r["status"],
                       "gbit_avg": r.get("gbit_avg"),
                       "rss_peak_mib": r.get("rss_peak_mib"),
                       "why": r.get("why", "")} for r in done],
        }
        with open(os.path.join(args.out_dir, "load-summary.json"), "w") as f:
            json.dump(summary, f, indent=1)
        print(f"\nитог: {len(done)} протоколов, "
              f"{sum(1 for r in done if r['status'] == 'OK')} OK, "
              f"сводка в {args.out_dir}/load-summary.json", flush=True)


if __name__ == "__main__":
    main()
