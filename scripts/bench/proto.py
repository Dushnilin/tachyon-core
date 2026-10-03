#!/usr/bin/env python3
"""Protocol-by-protocol comparison: tachyon-core vs reference sing-box (Linux, stdlib only).

Every case is a chain  load -> [client proxy] ==protocol==> [server proxy] -> sink
built from the same sing-box JSON for every implementation, so a number is a
property of the implementation and not of the config.

  Part A  protocols that both implementations can serve (server inbound exists
          in tachyon-core): the full 2x2 grid, client x server.
            diagonal cells   tachyon->tachyon vs ref->ref   speed, CPU, latency
            crossed cells    tachyon->ref and ref->tachyon  interop (works or not)
  Part B  transports/protocols where tachyon-core has no server (ws, grpc,
          reality, hysteria2, tuic, ...): the reference serves, and the two
          clients are compared against that same server.

Each cell runs in a forked child under a hard timeout, so a hung protocol is a
row that says FAIL, not a hung benchmark. The client proxy is pinned to
CLIENT_CPUS, the server proxy to SERVER_CPUS, load and sink to the rest.

    proto.py --tachyon /bench/tachyon-core --ref /bench/sing-box-lx --out proto.json
"""
import argparse
import base64
import json
import multiprocessing
import os
import socket
import ssl
import statistics
import struct
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bench  # noqa: E402

SERVER_PORT = 45003
REALITY_DEST_PORT = 45004
UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
SHORT_ID = "0123456789abcdef"
CELL_TIMEOUT = 240

# thresholds for the verdict column: tachyon must be within these of the reference
MIN_SPEED_RATIO = 0.90
MAX_COST_RATIO = 1.10


# ------------------------------------------------------------------------ cases
def b64(n):
    return base64.b64encode(bytes(range(1, n + 1))).decode()


def tls_server(certs, alpn=None):
    t = {
        "enabled": True,
        "server_name": "localhost",
        "certificate_path": certs["crt"],
        "key_path": certs["key"],
    }
    if alpn:
        t["alpn"] = alpn
    return t


def tls_client(alpn=None):
    t = {"enabled": True, "server_name": "localhost", "insecure": True}
    if alpn:
        t["alpn"] = alpn
    return t


def build_cases(certs, reality):
    """-> list of dicts: name, part ('A'|'B'), server (inbound), client (outbound)."""
    tls_s, tls_c = tls_server(certs), tls_client()
    cases = []

    def add(name, part, server, client):
        cases.append({"name": name, "part": part, "server": server, "client": client})

    # ---- Part A: shadowsocks
    for label, method, pw in [
        ("ss-aes-128-gcm", "aes-128-gcm", "bench-pass"),
        ("ss-aes-256-gcm", "aes-256-gcm", "bench-pass"),
        ("ss-chacha20-poly1305", "chacha20-ietf-poly1305", "bench-pass"),
        ("ss2022-aes-128-gcm", "2022-blake3-aes-128-gcm", b64(16)),
        ("ss2022-aes-256-gcm", "2022-blake3-aes-256-gcm", b64(32)),
        ("ss2022-chacha20", "2022-blake3-chacha20-poly1305", b64(32)),
    ]:
        add(label, "A",
            {"type": "shadowsocks", "method": method, "password": pw},
            {"type": "shadowsocks", "method": method, "password": pw})

    # ---- Part A: vmess / vless / trojan, plain and tls
    vmess_s = {"type": "vmess", "users": [{"name": "u", "uuid": UUID, "alterId": 0}]}
    vmess_c = {"type": "vmess", "uuid": UUID, "security": "auto"}
    add("vmess", "A", dict(vmess_s), dict(vmess_c))
    add("vmess-tls", "A", dict(vmess_s, tls=tls_s), dict(vmess_c, tls=tls_c))

    vless_s = {"type": "vless", "users": [{"name": "u", "uuid": UUID}]}
    vless_c = {"type": "vless", "uuid": UUID}
    add("vless", "A", dict(vless_s), dict(vless_c))
    add("vless-tls", "A", dict(vless_s, tls=tls_s), dict(vless_c, tls=tls_c))
    vision_s = {"type": "vless", "users": [{"name": "u", "uuid": UUID, "flow": "xtls-rprx-vision"}]}
    vision_c = {"type": "vless", "uuid": UUID, "flow": "xtls-rprx-vision"}
    add("vless-tls-vision", "A", dict(vision_s, tls=tls_s), dict(vision_c, tls=tls_c))

    trojan_s = {"type": "trojan", "users": [{"name": "u", "password": "bench-pass"}]}
    trojan_c = {"type": "trojan", "password": "bench-pass"}
    add("trojan-tls", "A", dict(trojan_s, tls=tls_s), dict(trojan_c, tls=tls_c))

    # ---- Part B: transports on the reference server
    transports = {
        "ws": {"type": "ws", "path": "/bench"},
        "grpc": {"type": "grpc", "service_name": "bench"},
        "httpupgrade": {"type": "httpupgrade", "path": "/bench"},
        "h2": {"type": "http", "path": "/bench"},
        "xhttp": {"type": "xhttp", "path": "/bench"},
    }
    for tname, tr in transports.items():
        add(f"vless-{tname}-tls", "B",
            dict(vless_s, tls=tls_s, transport=tr), dict(vless_c, tls=tls_c, transport=tr))
    for tname in ("ws", "grpc"):
        tr = transports[tname]
        add(f"vmess-{tname}-tls", "B",
            dict(vmess_s, tls=tls_s, transport=tr), dict(vmess_c, tls=tls_c, transport=tr))
        add(f"trojan-{tname}-tls", "B",
            dict(trojan_s, tls=tls_s, transport=tr), dict(trojan_c, tls=tls_c, transport=tr))

    mux = {"enabled": True, "protocol": "h2mux"}
    add("vless-tls-h2mux", "B",
        dict(vless_s, tls=tls_s, multiplex={"enabled": True}),
        dict(vless_c, tls=tls_c, multiplex=mux))

    if reality:
        r_server_tls = {
            "enabled": True,
            "server_name": "localhost",
            "reality": {
                "enabled": True,
                "handshake": {"server": "127.0.0.1", "server_port": REALITY_DEST_PORT},
                "private_key": reality["private"],
                "short_id": [SHORT_ID],
            },
        }
        r_client_tls = {
            "enabled": True,
            "server_name": "localhost",
            "utls": {"enabled": True, "fingerprint": "chrome"},
            "reality": {"enabled": True, "public_key": reality["public"], "short_id": SHORT_ID},
        }
        add("vless-reality-vision", "B",
            dict(vision_s, tls=r_server_tls), dict(vision_c, tls=r_client_tls))

    # ---- Part B: quic-based
    add("hysteria2", "B",
        {"type": "hysteria2", "users": [{"password": "bench-pass"}],
         "tls": tls_server(certs, ["h3"])},
        {"type": "hysteria2", "password": "bench-pass", "tls": tls_client(["h3"])})
    add("tuic", "B",
        {"type": "tuic", "users": [{"uuid": UUID, "password": "bench-pass"}],
         "congestion_control": "bbr", "tls": tls_server(certs, ["h3"])},
        {"type": "tuic", "uuid": UUID, "password": "bench-pass",
         "congestion_control": "bbr", "udp_relay_mode": "native", "tls": tls_client(["h3"])})
    return cases


# ------------------------------------------------------------------ processes
def parse_cpus(spec):
    out = set()
    for part in spec.split(","):
        lo, _, hi = part.partition("-")
        out.update(range(int(lo), int(hi or lo) + 1))
    return out


def server_cfg(case):
    inbound = dict(case["server"], tag="in", listen="127.0.0.1", listen_port=SERVER_PORT)
    return {
        "log": {"level": os.environ.get("PROTO_LOG", "error")},
        "inbounds": [inbound],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"},
    }


def client_cfg(case):
    out = dict(case["client"], tag="proxy", server="127.0.0.1", server_port=SERVER_PORT)
    return {
        "log": {"level": os.environ.get("PROTO_LOG", "error")},
        "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1",
                      "listen_port": bench.PROXY_PORT}],
        "outbounds": [out],
        "route": {"final": "proxy"},
    }


class Proc:
    def __init__(self, path, cfg, cpus, workdir, tag):
        self.cfg_path = os.path.join(workdir, f"{tag}.json")
        with open(self.cfg_path, "w") as f:
            json.dump(cfg, f)
        self.err_path = os.path.join(workdir, f"{tag}.err")
        self.err = open(self.err_path, "w")
        self.path, self.cpus = path, cpus
        self.p = None

    def check(self):
        r = subprocess.run([self.path, "check", "-c", self.cfg_path],
                           capture_output=True, text=True, timeout=30)
        return r.returncode == 0, (r.stdout + r.stderr).strip()

    def start(self):
        self.p = subprocess.Popen(
            [self.path, "run", "-c", self.cfg_path],
            stdout=self.err, stderr=self.err,
            preexec_fn=lambda: os.sched_setaffinity(0, self.cpus),
        )

    def alive(self):
        return self.p is not None and self.p.poll() is None

    def tail(self, n=4):
        self.err.flush()
        with open(self.err_path, errors="replace") as f:
            return " | ".join(l.strip() for l in f.readlines()[-n:] if l.strip())

    def stop(self):
        if self.p and self.p.poll() is None:
            self.p.terminate()
            try:
                self.p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.p.kill()
                self.p.wait()


def probe(deadline_s=25):
    """One echo through the chain, retried while the endpoints come up."""
    deadline = time.time() + deadline_s
    last = "no attempt"
    while time.time() < deadline:
        s = None
        try:
            s = socket.create_connection(("127.0.0.1", bench.PROXY_PORT), timeout=3)
            s.settimeout(6)
            s.sendall(b"\x05\x01\x00")
            assert bench.recvn(s, 2) == b"\x05\x00"
            s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1")
                      + struct.pack(">H", bench.SINK_PORT))
            reply = bench.recvn(s, 10)
            assert reply[1] == 0, f"socks reply {reply[1]}"
            s.sendall(bench.MODE_ECHO + b"p" * 64)
            assert bench.recvn(s, 64) == b"p" * 64
            return None
        except Exception as e:  # noqa: BLE001 - every failure is the same: not up yet
            last = f"{type(e).__name__}: {e}"
            time.sleep(0.4)
        finally:
            if s:
                s.close()
    return last


def connect_times(n=20):
    """Median time to a first echoed byte over a brand-new proxied connection."""
    out = []
    for _ in range(n):
        t = time.perf_counter()
        s = bench.socks_connect(True, bench.MODE_ECHO)
        s.sendall(b"c" * 64)
        bench.recvn(s, 64)
        out.append((time.perf_counter() - t) * 1000)
        s.close()
    return statistics.median(out)


def run_cell(tachyon_role, case, bins, cpus, runs, seconds, rounds, result):
    """Body of a forked child: one (client impl, server impl, case) cell."""
    client_impl, server_impl = tachyon_role
    res = {"case": case["name"], "client": client_impl, "server": server_impl}
    work = tempfile.mkdtemp()
    server = Proc(bins[server_impl], server_cfg(case), cpus["server"], work, "server")
    client = Proc(bins[client_impl], client_cfg(case), cpus["client"], work, "client")
    try:
        for who, proc in (("server", server), ("client", client)):
            ok, msg = proc.check()
            if not ok:
                res.update(status="REJECT", why=f"{who} check: {msg[-200:]}")
                return
        server.start()
        time.sleep(0.4)
        client.start()
        bench.wait_listen(bench.PROXY_PORT, timeout=15)
        why = probe()
        if why:
            dead = " (server died)" if not server.alive() else ""
            dead += " (client died)" if not client.alive() else ""
            res.update(status="FAIL", why=f"{why}{dead} s:[{server.tail()}] c:[{client.tail()}]")
            return
        res["connect_ms"] = connect_times()
        lat = [bench.measure_latency(True, rounds) for _ in range(2)]
        res["p50_us"] = statistics.median(x["p50_us"] for x in lat)
        res["p99_us"] = statistics.median(x["p99_us"] for x in lat)
        for streams in (1, 8):
            samples = []
            for _ in range(runs):
                s_cpu0 = bench.cpu_seconds(server.p.pid)
                r = bench.measure_throughput(True, streams, seconds, client.p.pid)
                s_cpu1 = bench.cpu_seconds(server.p.pid)
                gib = r["gbit_s"] * 1e9 / 8 * seconds / (1 << 30)
                r["server_cpu_s_per_gib"] = (s_cpu1 - s_cpu0) / gib if gib else None
                samples.append(r)
            samples.sort(key=lambda r: r["gbit_s"])
            m = samples[len(samples) // 2]
            cc, sc = m["proxy_cpu_s_per_gib"], m["server_cpu_s_per_gib"]
            res[f"tput_{streams}"] = {
                "gbit_s": m["gbit_s"],
                "client_cpu_s_per_gib": cc,
                "server_cpu_s_per_gib": sc,
                "cpu_s_per_gib": (cc + sc) if cc is not None and sc is not None else None,
            }
        res["client_rss_mib"] = bench.proc_status(client.p.pid)["VmHWM"]
        res["server_rss_mib"] = bench.proc_status(server.p.pid)["VmHWM"]
        res["status"] = "OK"
    except Exception as e:  # noqa: BLE001
        res.update(status="FAIL", why=f"{type(e).__name__}: {e} c:[{client.tail()}]")
    finally:
        client.stop()
        server.stop()
        result.send(res)


def run_cell_guarded(*args):
    ctx = multiprocessing.get_context("fork")
    rx, tx = ctx.Pipe(duplex=False)
    child = ctx.Process(target=run_cell, args=(*args, tx))
    child.start()
    tx.close()
    child.join(CELL_TIMEOUT)
    if child.is_alive():
        child.kill()
        child.join()
        subprocess.run(["pkill", "-f", "tachyon-core run|sing-box.* run"], check=False)
        role, case = args[0], args[1]
        return {"case": case["name"], "client": role[0], "server": role[1],
                "status": "FAIL", "why": f"timeout after {CELL_TIMEOUT}s"}
    return rx.recv() if rx.poll() else {
        "case": args[1]["name"], "client": args[0][0], "server": args[0][1],
        "status": "FAIL", "why": "cell exited without a result"}


# ------------------------------------------------------------------ fixtures
def make_certs(work):
    crt, key = os.path.join(work, "localhost.crt"), os.path.join(work, "localhost.key")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
         "-nodes", "-keyout", key, "-out", crt, "-days", "2", "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
        check=True, capture_output=True)
    return {"crt": crt, "key": key}


def make_reality(ref):
    r = subprocess.run([ref, "generate", "reality-keypair"], capture_output=True, text=True)
    vals = dict(l.split(": ", 1) for l in r.stdout.splitlines() if ": " in l)
    if "PrivateKey" not in vals or "PublicKey" not in vals:
        return None
    return {"private": vals["PrivateKey"], "public": vals["PublicKey"]}


def run_tls_dest(certs, cpus):
    """The 'real site' a reality server impersonates: completes a TLS handshake."""
    os.sched_setaffinity(0, cpus)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certs["crt"], certs["key"])
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", REALITY_DEST_PORT))
    srv.listen(64)
    while True:
        c, _ = srv.accept()
        try:
            c.settimeout(3)
            with ctx.wrap_socket(c, server_side=True) as t:
                t.recv(1)
        except OSError:
            pass


# --------------------------------------------------------------------- report
def ratio(a, b):
    return a / b if a is not None and b else None


def fmt(v, spec="{:.1f}", dash="-"):
    return dash if v is None else spec.format(v)


def verdict(t, r):
    """tachyon cell vs reference cell -> (text, lost: bool)."""
    if t["status"] != "OK" or r["status"] != "OK":
        return "n/a", False
    losses = []
    for key in ("tput_1", "tput_8"):
        sp = ratio(t[key]["gbit_s"], r[key]["gbit_s"])
        if sp is not None and sp < MIN_SPEED_RATIO:
            losses.append(f"{key} {sp:.2f}x")
        # CPU only matters when the proxies are not both maxed on the same wall
        cp = ratio(t[key]["cpu_s_per_gib"], r[key]["cpu_s_per_gib"])
        if cp is not None and cp > MAX_COST_RATIO and sp is not None and sp < 1.0:
            losses.append(f"{key} cpu {cp:.2f}x")
    pl = ratio(t["p50_us"], r["p50_us"])
    if pl is not None and pl > MAX_COST_RATIO:
        losses.append(f"p50 {pl:.2f}x")
    if t["connect_ms"] > r["connect_ms"] * 1.5 + 2:
        losses.append(f"connect {t['connect_ms']:.1f} vs {r['connect_ms']:.1f} ms")
    return ("LOSS: " + ", ".join(losses), True) if losses else ("ok", False)


def report(results, ref_name):
    by = {}
    for r in results:
        by.setdefault(r["case"], {})[(r["client"], r["server"])] = r
    lines = []
    losses = []
    interop_bad = []
    for part, title in (
        ("A", "Part A: both sides implemented (client x server grid)"),
        ("B", "Part B: reference server, tachyon-core vs reference client"),
    ):
        lines += [f"\n### {title}\n"]
        if part == "A":
            lines += [
                "| case | T->T 1s | T->T 8s | ref->ref 1s | ref->ref 8s | cpu T/ref (8s) | p50 us T/ref | connect ms T/ref | T->ref | ref->T | verdict |",
                "|---|---|---|---|---|---|---|---|---|---|---|",
            ]
        else:
            lines += [
                "| case | T 1s | T 8s | ref 1s | ref 8s | cpu T/ref (8s) | p50 us T/ref | connect ms T/ref | verdict |",
                "|---|---|---|---|---|---|---|---|---|",
            ]
        for name, cells in by.items():
            if cells and next(iter(cells.values())).get("part") != part:
                continue
            tt = cells.get(("tachyon", "tachyon" if part == "A" else "ref"))
            rr = cells.get(("ref", "ref"))
            if not tt or not rr:
                continue

            def g(c, k):
                return fmt(c[k]["gbit_s"]) if c["status"] == "OK" else c["status"]

            def pair(a, b, spec="{:.1f}"):
                if tt["status"] != "OK" or rr["status"] != "OK":
                    return "-"
                return f"{fmt(a, spec)}/{fmt(b, spec)}"

            cost = "-"
            if tt["status"] == "OK" and rr["status"] == "OK":
                cost = pair(tt["tput_8"]["cpu_s_per_gib"], rr["tput_8"]["cpu_s_per_gib"], "{:.3f}")
            v, lost = verdict(tt, rr)
            if lost:
                losses.append(f"{name}: {v}")
            row = [name, g(tt, "tput_1"), g(tt, "tput_8"), g(rr, "tput_1"), g(rr, "tput_8"),
                   cost,
                   pair(tt.get("p50_us"), rr.get("p50_us"), "{:.0f}"),
                   pair(tt.get("connect_ms"), rr.get("connect_ms")),
                   ]
            if part == "A":
                for key in (("tachyon", "ref"), ("ref", "tachyon")):
                    c = cells.get(key)
                    status = c["status"] if c else "-"
                    if c and c["status"] != "OK":
                        interop_bad.append(f"{name} {key[0]}->{key[1]}: {c['status']} {c.get('why', '')}")
                    row.append(status)
            row.append(v)
            lines.append("| " + " | ".join(row) + " |")
    failed = [r for r in results if r["status"] != "OK"]
    lines += ["\n### Failures and rejects\n"]
    lines += [f"- `{r['case']}` {r['client']}->{r['server']}: **{r['status']}** {r.get('why', '')}"
              for r in failed] or ["none"]
    lines += ["\n### Verdict\n",
              f"Reference: `{ref_name}`. A loss is speed under {MIN_SPEED_RATIO:.0%} of the reference, "
              f"or latency/CPU over {MAX_COST_RATIO:.0%}, or a slower connect.\n"]
    lines += [f"- {x}" for x in losses] or ["- no case loses to the reference"]
    return "\n".join(lines), losses, interop_bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tachyon", required=True)
    ap.add_argument("--ref", required=True)
    ap.add_argument("--ref-name", default="sing-box-lx")
    ap.add_argument("--client-cpus", default="0-1")
    ap.add_argument("--server-cpus", default="2-3")
    ap.add_argument("--seconds", type=int, default=3)
    ap.add_argument("--runs", type=int, default=3, help="throughput runs per cell, median kept")
    ap.add_argument("--rounds", type=int, default=5000, help="latency round trips")
    ap.add_argument("--only", default="", help="substring filter on case names")
    ap.add_argument("--part", default="AB", help="A, B or AB")
    ap.add_argument("--no-cross", action="store_true", help="skip the crossed interop cells")
    ap.add_argument("--out", default="proto-result.json")
    args = ap.parse_args()

    cpus = {"client": parse_cpus(args.client_cpus), "server": parse_cpus(args.server_cpus)}
    load = set(range(os.cpu_count())) - cpus["client"] - cpus["server"] or cpus["client"]
    os.sched_setaffinity(0, load)
    bins = {"tachyon": args.tachyon, "ref": args.ref}

    work = tempfile.mkdtemp()
    certs = make_certs(work)
    reality = make_reality(args.ref)
    ctx = multiprocessing.get_context("fork")
    sink = ctx.Process(target=bench.run_sink, args=(load,), daemon=True)
    sink.start()
    bench.wait_listen(bench.SINK_PORT)
    if reality:
        dest = ctx.Process(target=run_tls_dest, args=(certs, load), daemon=True)
        dest.start()
        bench.wait_listen(REALITY_DEST_PORT)

    cases = [c for c in build_cases(certs, reality)
             if c["part"] in args.part and args.only in c["name"]]
    results = []
    for case in cases:
        grid = [("tachyon", "tachyon"), ("ref", "ref")] if case["part"] == "A" else [
            ("tachyon", "ref"), ("ref", "ref")]
        if case["part"] == "A" and not args.no_cross:
            grid += [("tachyon", "ref"), ("ref", "tachyon")]
        for role in grid:
            r = run_cell_guarded(role, case, bins, cpus, args.runs, args.seconds, args.rounds)
            r["part"] = case["part"]
            results.append(r)
            line = f"{case['name']:24s} {role[0]:>7s}->{role[1]:<7s} {r['status']}"
            if r["status"] == "OK":
                line += (f"  1s {r['tput_1']['gbit_s']:5.1f}  8s {r['tput_8']['gbit_s']:5.1f} Gbit/s"
                         f"  p50 {r['p50_us']:5.0f} us  conn {r['connect_ms']:5.1f} ms")
            else:
                line += "  " + r.get("why", "")[:160]
            print(line, flush=True)

    text, losses, interop_bad = report(results, args.ref_name)
    out = {"cpu": next((l.split(":")[1].strip() for l in open("/proc/cpuinfo")
                        if l.startswith("model name")), "?"),
           "kernel": os.uname().release, "ref": args.ref_name,
           "results": results, "losses": losses, "interop_failures": interop_bad}
    with open(args.out, "w") as f:
        json.dump(out, f, indent=2)
    with open(os.path.splitext(args.out)[0] + ".md", "w") as f:
        f.write(text + "\n")
    print(text)


if __name__ == "__main__":
    main()
