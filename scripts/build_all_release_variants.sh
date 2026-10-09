#!/usr/bin/env bash
set -euo pipefail

cd /src
mkdir -p dist
VER="v0.0.1"

pack_one() {
    local edition="$1"  # "full" or "lite"
    local arch="$2"     # e.g. "x86_64-musl"
    local bin="$3"
    
    local out_prefix="tachyon-core"
    if [ "$edition" = "lite" ]; then
        out_prefix="tachyon-core-lite"
    fi
    local out_name="${out_prefix}-${arch}"
    local tar_name="${out_name}-${VER}.tar.gz"
    
    echo "=== Packaging $edition $arch -> dist/${tar_name} ==="
    cp "${bin}" "dist/${out_name}"
    chmod +x "dist/${out_name}"
    tar -czf "dist/${tar_name}" -C dist "${out_name}"
    rm -f "dist/${out_name}"
}

echo "=== Packaging Linux x86_64 Musl FULL (already compiled and validated) ==="
pack_one "full" "x86_64-musl" "target/full-x86_64-musl/tachyon-core"

echo "=== Building Linux x86_64 Musl LITE ==="
cargo build -p core-cli --release --target x86_64-unknown-linux-musl --no-default-features --features lite
mkdir -p target/lite-x86_64-musl
cp target/x86_64-unknown-linux-musl/release/tachyon-core target/lite-x86_64-musl/tachyon-core
pack_one "lite" "x86_64-musl" "target/lite-x86_64-musl/tachyon-core"

echo "=== Building AArch64 Musl FULL ==="
rustup target add aarch64-unknown-linux-musl || true
cargo build -p core-cli --release --target aarch64-unknown-linux-musl
mkdir -p target/full-aarch64-musl
cp target/aarch64-unknown-linux-musl/release/tachyon-core target/full-aarch64-musl/tachyon-core
pack_one "full" "aarch64-musl" "target/full-aarch64-musl/tachyon-core"

echo "=== Building AArch64 Musl LITE ==="
cargo build -p core-cli --release --target aarch64-unknown-linux-musl --no-default-features --features lite
mkdir -p target/lite-aarch64-musl
cp target/aarch64-unknown-linux-musl/release/tachyon-core target/lite-aarch64-musl/tachyon-core
pack_one "lite" "aarch64-musl" "target/lite-aarch64-musl/tachyon-core"

echo "=== Building ARMv7 Musl FULL ==="
rustup target add armv7-unknown-linux-musleabihf || true
RUSTFLAGS='-C linker=rust-lld -C link-self-contained=yes' cargo build -p core-cli --release --target armv7-unknown-linux-musleabihf
mkdir -p target/full-armv7-musl
cp target/armv7-unknown-linux-musleabihf/release/tachyon-core target/full-armv7-musl/tachyon-core
pack_one "full" "armv7-musl" "target/full-armv7-musl/tachyon-core"

echo "=== Building ARMv7 Musl LITE ==="
RUSTFLAGS='-C linker=rust-lld -C link-self-contained=yes' cargo build -p core-cli --release --target armv7-unknown-linux-musleabihf --no-default-features --features lite
mkdir -p target/lite-armv7-musl
cp target/armv7-unknown-linux-musleabihf/release/tachyon-core target/lite-armv7-musl/tachyon-core
pack_one "lite" "armv7-musl" "target/lite-armv7-musl/tachyon-core"

echo "=== Building ARMv6 Musl FULL ==="
rustup target add arm-unknown-linux-musleabi || true
RUSTFLAGS='-C linker=rust-lld -C link-self-contained=yes' cargo build -p core-cli --release --target arm-unknown-linux-musleabi
mkdir -p target/full-armv6-musl
cp target/arm-unknown-linux-musleabi/release/tachyon-core target/full-armv6-musl/tachyon-core
pack_one "full" "armv6-musl" "target/full-armv6-musl/tachyon-core"

echo "=== Building ARMv6 Musl LITE ==="
RUSTFLAGS='-C linker=rust-lld -C link-self-contained=yes' cargo build -p core-cli --release --target arm-unknown-linux-musleabi --no-default-features --features lite
mkdir -p target/lite-armv6-musl
cp target/arm-unknown-linux-musleabi/release/tachyon-core target/lite-armv6-musl/tachyon-core
pack_one "lite" "armv6-musl" "target/lite-armv6-musl/tachyon-core"

echo "=== Building Linux amd64 GNU FULL ==="
cargo build -p core-cli --release --target x86_64-unknown-linux-gnu
mkdir -p target/full-linux-amd64
cp target/x86_64-unknown-linux-gnu/release/tachyon-core target/full-linux-amd64/tachyon-core
pack_one "full" "linux-amd64" "target/full-linux-amd64/tachyon-core"

echo "=== Building Linux amd64 GNU LITE ==="
cargo build -p core-cli --release --target x86_64-unknown-linux-gnu --no-default-features --features lite
mkdir -p target/lite-linux-amd64
cp target/x86_64-unknown-linux-gnu/release/tachyon-core target/lite-linux-amd64/tachyon-core
pack_one "lite" "linux-amd64" "target/lite-linux-amd64/tachyon-core"

echo "=== Packaging MIPS & MIPSEL ==="
if [ -f target/mipsel-unknown-linux-musl/release/tachyon-core ]; then
    pack_one "full" "mipsel-musl" "target/mipsel-unknown-linux-musl/release/tachyon-core"
fi
if [ -f target/mips-unknown-linux-musl/release/tachyon-core ]; then
    pack_one "full" "mips-musl" "target/mips-unknown-linux-musl/release/tachyon-core"
fi

echo "=== Building OpenWrt Package Archive ==="
tar -czf "dist/tachyon-core-openwrt-package-v0.0.1.tar.gz" openwrt/

echo "=== Done with Linux release variants! ==="
ls -lh dist/
