//! Manual userspace-relay comparison, using System on both revisions.
//! Counts live Rust allocation sizes, not RSS, and forces the buffered path
//! with duplex streams. The transfer phase is a local smoke benchmark, not a
//! TLS/WAN speed claim. Keep it ignored so timing does not become a CI gate.

use core_runtime::inbound::{Conn, pump_conn_tracked};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct CountAlloc;
static LIVE: AtomicIsize = AtomicIsize::new(0);
unsafe impl GlobalAlloc for CountAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        unsafe { System.dealloc(p, layout) };
    }
}
#[global_allocator]
static ALLOC: CountAlloc = CountAlloc;

async fn settle() {
    tokio::time::sleep(Duration::from_millis(100)).await;
}

#[tokio::test]
#[ignore = "manual live-allocation and throughput comparison; run with --ignored --nocapture"]
async fn memory_and_throughput_probe() {
    let mut peers = Vec::new();
    let mut tasks = Vec::new();
    settle().await;
    let initial = LIVE.load(Ordering::Relaxed);
    for _ in 0..80 {
        let (client, caller) = tokio::io::duplex(65536);
        let (upstream, server) = tokio::io::duplex(65536);
        tasks.push(tokio::spawn(async move {
            pump_conn_tracked(client, Conn::Plain(Box::new(upstream)), &[], None)
                .await
                .unwrap();
        }));
        peers.push((caller, server));
    }
    for (caller, server) in &mut peers {
        caller.write_all(b"warm upstream").await.unwrap();
        let mut data = [0; 13];
        server.read_exact(&mut data).await.unwrap();
        server.write_all(b"warm downstream").await.unwrap();
        let mut data = [0; 15];
        caller.read_exact(&mut data).await.unwrap();
    }
    settle().await;
    println!(
        "PROBE held80_live_delta_bytes={}",
        LIVE.load(Ordering::Relaxed) - initial
    );
    drop(peers);
    for task in tasks {
        task.await.unwrap();
    }
    settle().await;
    println!(
        "PROBE closed_live_delta_bytes={}",
        LIVE.load(Ordering::Relaxed) - initial
    );

    for chunk in [4096, 65536, 131070] {
        let payload = vec![0x5a; chunk];
        let total = 64 * 1024 * 1024 / chunk * chunk;
        let mut elapsed = Vec::new();
        for _ in 0..5 {
            let (client, mut caller) = tokio::io::duplex(262144);
            let (upstream, mut server) = tokio::io::duplex(262144);
            let relay = tokio::spawn(async move {
                pump_conn_tracked(client, Conn::Plain(Box::new(upstream)), &[], None)
                    .await
                    .unwrap();
            });
            let drain = tokio::spawn(async move {
                let mut data = vec![0; 131070];
                let mut received = 0;
                loop {
                    let n = server.read(&mut data).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    assert!(data[..n].iter().all(|b| *b == 0x5a));
                    received += n;
                }
                assert_eq!(received, total);
                server.shutdown().await.unwrap();
            });
            let start = Instant::now();
            for _ in 0..total / chunk {
                caller.write_all(&payload).await.unwrap();
            }
            caller.shutdown().await.unwrap();
            drain.await.unwrap();
            relay.await.unwrap();
            elapsed.push(start.elapsed().as_secs_f64());
        }
        elapsed.sort_by(f64::total_cmp);
        println!(
            "PROBE chunk={chunk} median_mib_s={:.2} samples_seconds={elapsed:?}",
            total as f64 / 1048576.0 / elapsed[2]
        );
    }
}
