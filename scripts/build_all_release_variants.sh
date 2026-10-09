#!/usr/bin/env bash
set -euo pipefail

cd /src
mkdir -p dist
VER="v0.0.1"

pack_one() {
    local arch="$1"     # e.g. "x86_64-musl"
    local bin="$2"
    
    local out_name="tachyon-core-${arch}"
    local tar_name="${out_name}-${VER}.tar.gz"
    
    echo "=== Packaging $arch -> dist/${tar_name} ==="
    cp "${bin}" "dist/${out_name}"
    chmod +x "dist/${out_name}"
    tar -czf "dist/${tar_name}" -C dist "${out_name}"
    rm -f "dist/${out_name}"
}

echo "=== Packaging Linux x86_64 Musl (already compiled and validated) ==="
pack_one "x86_64-musl" "target/full-x86_64-musl/tachyon-core"

echo "=== Building AArch64 Musl ==="
rustup target add aarch64-unknown-linux-musl || true
cargo build -p core-cli --release --target aarch64-unknown-linux-musl
mkdir -p target/full-aarch64-musl
cp target/aarch64-unknown-linux-musl/release/tachyon-core target/full-aarch64-musl/tachyon-core
pack_one "aarch64-musl" "target/full-aarch64-musl/tachyon-core"

echo "=== Building ARMv7 Musl ==="
rustup target add armv7-unknown-linux-musleabihf || true
RUSTFLAGS='-C linker=rust-lld -C link-self-contained=yes' cargo build -p core-cli --release --target armv7-unknown-linux-musleabihf
mkdir -p target/full-armv7-musl
cp target/armv7-unknown-linux-musleabihf/release/tachyon-core target/full-armv7-musl/tachyon-core
pack_one "armv7-musl" "target/full-armv7-musl/tachyon-core"

echo "=== Building ARMv6 Musl ==="
rustup target add arm-unknown-linux-musleabi || true
RUSTFLAGS='-C linker=rust-lld -C link-self-contained=yes' cargo build -p core-cli --release --target arm-unknown-linux-musleabi
mkdir -p target/full-armv6-musl
cp target/arm-unknown-linux-musleabi/release/tachyon-core target/full-armv6-musl/tachyon-core
pack_one "armv6-musl" "target/full-armv6-musl/tachyon-core"

echo "=== Building Linux amd64 GNU ==="
cargo build -p core-cli --release --target x86_64-unknown-linux-gnu
mkdir -p target/full-linux-amd64
cp target/x86_64-unknown-linux-gnu/release/tachyon-core target/full-linux-amd64/tachyon-core
pack_one "linux-amd64" "target/full-linux-amd64/tachyon-core"

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
