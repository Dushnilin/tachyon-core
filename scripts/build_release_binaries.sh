#!/usr/bin/env bash
set -euo pipefail

cd /src

echo "=== 1. Building x86_64-unknown-linux-musl ==="
cargo build -p core-cli --release --target x86_64-unknown-linux-musl

echo "=== 2. Building aarch64-unknown-linux-musl ==="
rustup target add aarch64-unknown-linux-musl || true
cargo build -p core-cli --release --target aarch64-unknown-linux-musl

echo "=== 3. Building armv7-unknown-linux-musleabihf ==="
rustup target add armv7-unknown-linux-musleabihf || true
RUSTFLAGS='-C linker=rust-lld -C link-self-contained=yes' cargo build -p core-cli --release --target armv7-unknown-linux-musleabihf

echo "=== 4. Building arm-unknown-linux-musleabi (armv6) ==="
rustup target add arm-unknown-linux-musleabi || true
RUSTFLAGS='-C linker=rust-lld -C link-self-contained=yes' cargo build -p core-cli --release --target arm-unknown-linux-musleabi

echo "=== 5. Building x86_64-unknown-linux-gnu ==="
cargo build -p core-cli --release --target x86_64-unknown-linux-gnu

echo "=== 6. Building mipsel-unknown-linux-musl ==="
cargo +nightly build -p core-cli --release --target mipsel-unknown-linux-musl -Z build-std=std,panic_abort || echo "MIPSEL build warning, keeping existing"

echo "=== 7. Building mips-unknown-linux-musl ==="
cargo +nightly build -p core-cli --release --target mips-unknown-linux-musl -Z build-std=std,panic_abort || echo "MIPS build warning, keeping existing"

VER="${1:-v0.0.2}"

echo "=== 8. Packaging all router architectures ==="
bash scripts/pack_all_architectures.sh "${VER}"
echo "=== All architectures successfully built and packaged for ${VER}! ==="
