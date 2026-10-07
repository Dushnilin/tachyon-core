//! Not a test: a hand-run microbenchmark of the two AEADs at the exact shapes
//! the proxy seals, so the CPU cost seen in the protocol matrix can be split
//! into "the cipher" and "everything around the cipher" without perf, which
//! does not sample on the WSL2 PMU at all.
//!
//!     cargo test --release -p core-crypto --test perf_aead -- --ignored --nocapture
//!
//! Numbers reported per shape: ns/op, the GiB/s that implies for a stream of
//! such records, and the CPU-seconds per GiB that shape alone costs. The
//! per-record counts are the protocol's, not a guess: `ops/GiB = 2^30 / size`
//! for payloads, and the record rate of the protocol for the length blocks.
use aes_gcm::aead::{AeadInPlace, KeyInit, generic_array::GenericArray};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use core_crypto::fastchacha::ChaChaPoly;
use core_crypto::fastgcm::Gcm;
use std::hint::black_box;
use std::time::Instant;

/// Records of `size` bytes in one GiB of payload.
fn ops_per_gib(size: usize) -> f64 {
    (1u64 << 30) as f64 / size as f64
}

fn seal_shapes(name: &str, seal: &dyn Fn(&mut [u8]), sizes: &[usize]) {
    for &size in sizes {
        let mut buf = vec![0x5Au8; size];
        for _ in 0..64 {
            seal(black_box(&mut buf));
        }
        // ~150 ms of work at the speeds seen so far, never fewer than 64 ops
        // (the small blocks are measured by the hundred thousand)
        let iters = if size >= 1024 {
            (1.5e8 / (size as f64 * 3.0)).max(64.0) as u64
        } else {
            200_000
        };
        let t = Instant::now();
        for _ in 0..iters {
            seal(black_box(&mut buf));
        }
        let ns_op = t.elapsed().as_nanos() as f64 / iters as f64;
        let gib_s = size as f64 / ns_op;
        let s_per_gib = ns_op * ops_per_gib(size) / 1e9;
        println!(
            "{name:16} size {size:6}  ns/op {ns_op:10.1}  {gib_s:8.2} GiB/s  {s_per_gib:6.3} s/GiB"
        );
    }
}

#[test]
#[ignore = "microbenchmark, run by hand"]
fn perf_aead_shapes() {
    let gcm128 = Gcm::new(&[1u8; 16]);
    let gcm256 = Gcm::new(&[2u8; 32]);
    let chacha = ChaChaPoly::new(&[3u8; 32]);
    let nonce = [7u8; 12];

    // opens: the download path decrypts every chunk, so the same shapes as
    // seals, with a tag taken from a real seal so the tag check passes
    {
        println!("-- payload opens --");
        for size in [16usize, 18, 128, 15000, 16384, 65535] {
            let mut buf = vec![0x5Au8; size];
            let tag = gcm128.seal(&nonce, &[], &mut buf);
            let iters = if size >= 1024 {
                (1.5e8 / (size as f64 * 3.0)).max(64.0) as u64
            } else {
                200_000
            };
            let t = Instant::now();
            for _ in 0..iters {
                black_box(gcm128.open(black_box(&nonce), &[], &mut buf, &tag));
            }
            let ns_op = t.elapsed().as_nanos() as f64 / iters as f64;
            let gib_s = size as f64 / ns_op;
            let s_per_gib = ns_op * ops_per_gib(size) / 1e9;
            println!(
                "open gcm128       size {size:6}  ns/op {ns_op:10.1}  {gib_s:8.2} GiB/s  {s_per_gib:6.3} s/GiB"
            );
        }
    }

    // the payload shapes: 65535 = ss2022 max_chunk, 16383 = legacy 0x3FFF
    // chunk, 15000 = vmess WRITE_CHUNK
    let payloads = [65535usize, 16383, 15000];
    println!("-- payload seals --");
    seal_shapes(
        "gcm128",
        &|b| {
            black_box(gcm128.seal(&nonce, &[], b));
        },
        &payloads,
    );
    seal_shapes(
        "gcm256",
        &|b| {
            black_box(gcm256.seal(&nonce, &[], b));
        },
        &payloads,
    );
    seal_shapes(
        "chachapoly",
        &|b| {
            black_box(chacha.seal(&nonce, &[], b));
        },
        &payloads,
    );

    // the same shapes through the crates' own AVX2 backends: the question is
    // whether fastgcm/fastchacha beat them or are beaten by them
    println!("-- crate backends, same shapes --");
    let crate128 = Aes128Gcm::new_from_slice(&[1u8; 16]).expect("key");
    let crate256 = Aes256Gcm::new_from_slice(&[2u8; 32]).expect("key");
    let cratechacha = ChaCha20Poly1305::new_from_slice(&[3u8; 32]).expect("key");
    let g = GenericArray::from_slice(&nonce);
    seal_shapes(
        "crate-aes128",
        &|b| {
            black_box(
                crate128
                    .encrypt_in_place_detached(g, &[], b)
                    .expect("in place"),
            );
        },
        &payloads,
    );
    seal_shapes(
        "crate-aes256",
        &|b| {
            black_box(
                crate256
                    .encrypt_in_place_detached(g, &[], b)
                    .expect("in place"),
            );
        },
        &payloads,
    );
    seal_shapes(
        "crate-chacha",
        &|b| {
            black_box(
                cratechacha
                    .encrypt_in_place_detached(g, &[], b)
                    .expect("in place"),
            );
        },
        &payloads,
    );

    // the per-record side blocks: 2 = a plain length block, 18 = a vmess
    // authenticated-length block (2 bytes + tag). Reported with the record
    // rate of the protocol that seals them, because a length block's own
    // GiB/s means nothing.
    println!("-- length/auth blocks (ns/op, then s/GiB at that protocol's record rate) --");
    let seal128: &dyn Fn(&mut [u8]) = &|b| {
        black_box(gcm128.seal(&nonce, &[], b));
    };
    let sealchacha: &dyn Fn(&mut [u8]) = &|b| {
        black_box(chacha.seal(&nonce, &[], b));
    };
    for (name, seal) in [("gcm128", seal128), ("chachapoly", sealchacha)] {
        for (size, count_name, count) in [
            (2usize, "ss2022 16385/GiB", ops_per_gib(65535)),
            (2, "legacy 65541/GiB", ops_per_gib(16383)),
            (18, "vmess 71583/GiB", ops_per_gib(15000)),
        ] {
            let mut buf = vec![0x5Au8; size];
            for _ in 0..64 {
                seal(black_box(&mut buf));
            }
            let t = Instant::now();
            let iters = 200_000u64;
            for _ in 0..iters {
                seal(black_box(&mut buf));
            }
            let ns_op = t.elapsed().as_nanos() as f64 / iters as f64;
            println!(
                "{name:16} size {size:6}  ns/op {ns_op:10.1}  {count_name:20} {:6.3} s/GiB",
                ns_op * count / 1e9
            );
        }
    }

    // the open path once per shape, over a ciphertext that is restored by a
    // seal outside neither clock: open decrypts in place, and re-sealing the
    // plaintext with the same nonce restores the original ciphertext exactly,
    // so the loop is stable. The clock covers open+seal; open alone is that
    // minus the seal number measured above.
    println!("-- open (clocked as open+seal, restore by resealing) --");
    let mut buf = vec![0x5Au8; 65535];
    let tag = gcm128.seal(&nonce, &[], &mut buf);
    for _ in 0..64 {
        black_box(gcm128.open(&nonce, &[], &mut buf, &tag));
        gcm128.seal(&nonce, &[], &mut buf);
    }
    let t = Instant::now();
    let iters = 3000u64;
    for _ in 0..iters {
        black_box(gcm128.open(&nonce, &[], &mut buf, &tag));
        gcm128.seal(&nonce, &[], &mut buf);
    }
    let dt = t.elapsed().as_nanos() as f64 / iters as f64;
    println!("gcm128 open+seal 65535  ns/op {dt:.1} (seal alone is measured above)");
}
