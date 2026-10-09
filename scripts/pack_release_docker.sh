#!/usr/bin/env bash
set -euo pipefail

cd /src
mkdir -p dist
VER="v0.0.1"

echo "=== Packaging x86_64-unknown-linux-musl ==="
cp target/x86_64-unknown-linux-musl/release/tachyon-core dist/tachyon-core-x86_64-musl
chmod +x dist/tachyon-core-x86_64-musl
tar -czf "dist/tachyon-core-x86_64-musl-${VER}.tar.gz" -C dist tachyon-core-x86_64-musl

echo "=== Packaging aarch64-unknown-linux-musl ==="
cp target/aarch64-unknown-linux-musl/release/tachyon-core dist/tachyon-core-aarch64-musl
chmod +x dist/tachyon-core-aarch64-musl
tar -czf "dist/tachyon-core-aarch64-musl-${VER}.tar.gz" -C dist tachyon-core-aarch64-musl

echo "=== Packaging x86_64-unknown-linux-gnu ==="
cp target/x86_64-unknown-linux-gnu/release/tachyon-core dist/tachyon-core-x86_64-linux
chmod +x dist/tachyon-core-x86_64-linux
tar -czf "dist/tachyon-core-linux-amd64-${VER}.tar.gz" -C dist tachyon-core-x86_64-linux

echo "=== Building OpenWrt Package Archive ==="
tar -czf "dist/tachyon-core-openwrt-package-${VER}.tar.gz" openwrt/

echo "=== Generating Checksums ==="
cd dist
sha256sum *.tar.gz > SHA256SUMS
cat SHA256SUMS
echo "=== Done ==="
