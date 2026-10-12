//! Стабильность: живой бинарь под враждебной нагрузкой обязан оставаться жив,
//! продолжать обслуживать здоровые коннекты и возвращаться к базовой линии.
//!
//! Схема: mixed-инбаунд + direct, эхо-сток внутри теста. Базовая линия → круг
//! штормов (мусорные хендшейки, полурукопожатия, churn закрытых нахрапом
//! коннектов, обрывы посреди релея) → отстой → снова базовая линия. Главная
//! проверка — круг 2 не хуже круга 1: пик RSS между кругами не растёт, FD и
//! потоки возвращаются к базовой, а сквозной эхо-коннект проходит всё время,
//! включая саму нагрузку.
//!
//! Это регресс-гейт на минуты, а не выдержка. Долгая жизнь протоколов —
//! отдельная работа: scripts/bench/night_load.py (10k коннектов × 20 мин на
//! протокол на реальном устройстве). Точечный hot-reload —
//! crates/core-runtime/tests/hot_reload.rs (in-process, без падений коннектов).
//!
//! Linux-only: метрики берутся из /proc. STAB_ROUNDS (по умолчанию 2) и
//! STAB_CHURN (по умолчанию 8000) масштабируют прогон до выдержки; при
//! масштабировании критерий RSS — бюджет удержания на коннект (арены
//! отлаженного билда растут неравномерно, утечка на коннект — линейно).

#![cfg(target_os = "linux")]

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

/// Боксу даём щедрое время на старте: холодная сборка под нагруженной машиной
/// медленная, но зависший тест дороже упавшего.
const STARTUP: Duration = Duration::from_secs(30);
const IO: Duration = Duration::from_secs(2);

fn envu(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("a free port")
        .local_addr()
        .expect("its address")
        .port()
}

fn config(port: u16) -> Value {
    json!({
        "log": {"level": "error"},
        "inbounds": [{
            "type": "mixed",
            "tag": "in",
            "listen": "127.0.0.1",
            "listen_port": port
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"}
    })
}

/// Бокс под наблюдением: убить и переждать в конце обязан он всегда.
struct Proc(Child);

impl Proc {
    fn spawn(cfg: &Value) -> Self {
        let path = std::env::temp_dir().join("tachyon-core-stability.json");
        std::fs::write(&path, serde_json::to_vec(cfg).expect("json")).expect("write config");
        let child = Command::new(env!("CARGO_BIN_EXE_tachyon-core"))
            .args(["run", "-c"])
            .arg(&path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn tachyon-core run");
        Self(child)
    }

    fn pid(&self) -> u32 {
        self.0.id()
    }

    fn alive(&mut self) -> bool {
        self.0
            .try_wait()
            .map(|status| status.is_none())
            .unwrap_or(false)
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[derive(Clone, Copy)]
struct Sample {
    rss_kib: u64,
    hwm_kib: u64,
    fds: usize,
    threads: u64,
}

fn field(pid: u32, name: &str) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("proc status");
    status
        .lines()
        .find(|l| l.starts_with(name))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

fn sample(pid: u32) -> Sample {
    Sample {
        rss_kib: field(pid, "VmRSS:"),
        hwm_kib: field(pid, "VmHWM:"),
        fds: std::fs::read_dir(format!("/proc/{pid}/fd"))
            .map(|d| d.count())
            .unwrap_or(0),
        threads: field(pid, "Threads:"),
    }
}

fn wait_listen(port: u16) {
    let deadline = Instant::now() + STARTUP;
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "mixed-инбаунд не поднялся за {STARTUP:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Эхо-сток — конечная точка всех SOCKS-соединений теста. Нить detach'ится:
/// тест-процесс всё равно завершается.
fn echo_sink() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("echo bind");
    let addr = listener.local_addr().expect("echo addr");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { break };
            std::thread::spawn(move || {
                s.set_read_timeout(Some(IO)).ok();
                let mut buf = [0u8; 16384];
                loop {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

fn socks_connect(proxy: u16, target: SocketAddr) -> io::Result<TcpStream> {
    let mut s = TcpStream::connect(("127.0.0.1", proxy))?;
    s.set_read_timeout(Some(IO))?;
    s.set_write_timeout(Some(IO))?;
    s.write_all(b"\x05\x01\x00")?;
    let mut hello = [0u8; 2];
    s.read_exact(&mut hello)?;
    assert_eq!(hello, [5, 0], "приветствие socks отвергнуто: {hello:?}");
    let SocketAddr::V4(v4) = target else {
        return Err(io::Error::other("echo только IPv4"));
    };
    let mut req = vec![5, 1, 0, 1];
    req.extend_from_slice(&v4.ip().octets());
    req.extend_from_slice(&v4.port().to_be_bytes());
    s.write_all(&req)?;
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply)?;
    assert_eq!(reply[1], 0, "socks connect refused: {reply:?}");
    Ok(s)
}

/// Здоровый коннект целиком: приветствие, connect, 64 байта туда-обратно.
fn probe(proxy: u16, echo: SocketAddr) -> io::Result<Duration> {
    let t0 = Instant::now();
    let mut s = socks_connect(proxy, echo)?;
    let msg = [b'p'; 64];
    s.write_all(&msg)?;
    let mut back = [0u8; 64];
    s.read_exact(&mut back)?;
    if back != msg {
        return Err(io::Error::other("эхо вернулось не тем"));
    }
    Ok(t0.elapsed())
}

/// Мусорные хендшейки: байты, которых нет ни в одном протоколе, и закрытие
/// сразу или после shutdown(Write). Проверяет, что парсер хендшейка не падает
/// и не течёт. True-RST std не умеет (нужен SO_LINGER) — RST-ветку гоняют
/// python-харнессы (bench.py / night_load.py), здесь хватает FIN-шторма.
fn storm_garbage(proxy: u16, n: usize) {
    std::thread::scope(|sc| {
        for _ in 0..32 {
            sc.spawn(move || {
                for i in 0..n.div_ceil(32) {
                    let Ok(mut s) = TcpStream::connect(("127.0.0.1", proxy)) else {
                        continue;
                    };
                    s.set_read_timeout(Some(IO)).ok();
                    let junk = vec![0xA5 ^ (i as u8); 1 + (i % 64)];
                    let _ = s.write_all(&junk);
                    if i % 3 == 0 {
                        let _ = s.shutdown(Shutdown::Write);
                    }
                }
            });
        }
    });
}

/// Полурукопожатия: 1–3 байта приветствия и тишина — коннекты висят до
/// нашего закрытия. Ядро обязано держать их, а после снятия — отпустить
/// все ресурсы.
fn storm_dribble(proxy: u16, n: usize) {
    std::thread::scope(|sc| {
        for _ in 0..20 {
            sc.spawn(move || {
                for i in 0..n.div_ceil(20) {
                    let Ok(mut s) = TcpStream::connect(("127.0.0.1", proxy)) else {
                        continue;
                    };
                    let _ = s.write_all(&[5, 1, 0][..1 + (i % 3)]);
                    std::thread::sleep(Duration::from_secs(2));
                }
            });
        }
    });
}

/// Churn: закрытие сразу после приветствия, не дожидаясь ответа — ядро пишет
/// в уже закрытый сокет и отменяет работу на полпути.
fn storm_churn(proxy: u16, n: usize) {
    std::thread::scope(|sc| {
        for _ in 0..32 {
            sc.spawn(move || {
                for _ in 0..n.div_ceil(32) {
                    let Ok(mut s) = TcpStream::connect(("127.0.0.1", proxy)) else {
                        continue;
                    };
                    let _ = s.write_all(b"\x05\x01\x00");
                }
            });
        }
    });
}

/// Обрыв посреди релея: полное рукопожатие, заливка 256 КиБ без чтения
/// обратно (переполнение буфера возврата), падение на полпути.
fn storm_relay_abort(proxy: u16, echo: SocketAddr, n: usize) {
    std::thread::scope(|sc| {
        for _ in 0..16 {
            sc.spawn(move || {
                for _ in 0..n.div_ceil(16) {
                    let Ok(mut s) = socks_connect(proxy, echo) else {
                        continue;
                    };
                    let chunk = [b'a'; 4096];
                    for _ in 0..64 {
                        if s.write_all(&chunk).is_err() {
                            break;
                        }
                    }
                }
            });
        }
    });
}

fn show(label: &str, s: &Sample) {
    println!(
        "{label}: RSS {} КиБ (пик {}), FD {}, потоков {}",
        s.rss_kib, s.hwm_kib, s.fds, s.threads
    );
}

#[test]
fn hostile_storms_leave_the_core_at_baseline() {
    let proxy = free_port();
    let mut core = Proc::spawn(&config(proxy));
    wait_listen(proxy);
    let echo = echo_sink();
    std::thread::sleep(Duration::from_secs(2));
    let base = sample(core.pid());
    show("базовая", &base);

    let rounds = envu("STAB_ROUNDS", 2);
    let churn = envu("STAB_CHURN", 8000);
    let mut samples = Vec::new();
    for round in 1..=rounds {
        storm_garbage(proxy, 400);
        assert!(
            probe(proxy, echo).is_ok(),
            "прокси перестал отвечать под мусором (круг {round})"
        );

        storm_dribble(proxy, 80);

        // здоровый трафик идёт прямо ПОД churn, а не после него
        std::thread::scope(|sc| {
            sc.spawn(move || storm_churn(proxy, churn));
            for i in 0..20 {
                let latency = probe(proxy, echo).unwrap_or_else(|e| {
                    panic!("эхо под churn отвалилось: {e} (круг {round}, {i})")
                });
                assert!(
                    latency < Duration::from_secs(2),
                    "эхо под churn медленнее 2 с: {latency:?} (круг {round})"
                );
            }
        });

        storm_relay_abort(proxy, echo, 150);
        assert!(core.alive(), "бокс умер на круге {round}");

        std::thread::sleep(Duration::from_secs(3));
        let s = sample(core.pid());
        show(&format!("круг {round}"), &s);
        samples.push(s);
    }

    std::thread::sleep(Duration::from_secs(5));
    let fin = sample(core.pid());
    assert!(core.alive(), "бокс умер на отстое");
    let latency = probe(proxy, echo).expect("здоровый коннект после штормов");
    show("финал ", &fin);
    println!("эхо после штормов: {latency:?}");

    for (i, s) in samples.iter().enumerate() {
        assert!(
            s.fds <= base.fds + 8,
            "FD после круга {}: {} против базовой {}",
            i + 1,
            s.fds,
            base.fds
        );
        assert!(
            s.threads <= base.threads + 8,
            "потоки после круга {}: {} против базовой {}",
            i + 1,
            s.threads,
            base.threads
        );
    }
    assert!(
        fin.fds <= base.fds + 8,
        "FD на отстое: {} против базовой {}",
        fin.fds,
        base.fds
    );
    assert!(
        fin.threads <= base.threads + 8,
        "потоки на отстое: {} против базовой {}",
        fin.threads,
        base.threads
    );

    // Главный детектор утечки — на дефолтном гейте: RSS не растёт от круга к
    // кругу и оседает на отстое. 4 МиБ — доля аллокатора, а не роста.
    let scaled = rounds > 2 || churn > 8000;
    if scaled {
        // При масштабировании порог между кругами непригоден: арены
        // отлаженного билда растут от прогона к прогону неравномерно (замерено:
        // +16.7/+6.8/+3.1 и +2.3/+5.4 КиБ на разных прогонах). Вместо него —
        // бюджет удержания: 512 байт на закрытый коннект на арены и пулы
        // буферов; линейная утечка в 1 КиБ/коннект через этот бюджет не
        // проходит. Остановка на отстое без роста — отдельный assert ниже.
        let total_conns = rounds * churn;
        let budget_kib = base.rss_kib + 16 * 1024 + (total_conns / 2) as u64;
        assert!(
            fin.rss_kib <= budget_kib,
            "удержание после {} коннектов: RSS {} КиБ против бюджета {} КиБ",
            total_conns,
            fin.rss_kib,
            budget_kib
        );
    } else {
        for pair in samples.windows(2) {
            assert!(
                pair[1].rss_kib <= pair[0].rss_kib + 4 * 1024,
                "RSS вырос между кругами: {} -> {} КиБ",
                pair[0].rss_kib,
                pair[1].rss_kib
            );
        }
    }
    assert!(
        fin.rss_kib <= samples.last().expect("круги есть").rss_kib + 4 * 1024,
        "RSS на отстое выше, чем сразу после штормов: {} -> {} КиБ",
        samples.last().expect("круги есть").rss_kib,
        fin.rss_kib
    );
    let hwm_max = samples
        .iter()
        .map(|s| s.hwm_kib)
        .chain([fin.hwm_kib])
        .max()
        .expect("есть пики");
    assert!(
        hwm_max <= base.rss_kib + 96 * 1024,
        "пик RSS {} КиБ против базовой {} — шторм раздул ядро",
        hwm_max,
        base.rss_kib
    );
}
