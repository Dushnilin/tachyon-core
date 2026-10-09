#!/usr/bin/env bash
set -euo pipefail

cd /src
mkdir -p dist
rm -rf dist/*
VER="v0.0.1"

pack_arch() {
    local arch="$1"
    local bin_path="$2"
    local out_name="tachyon-core-${arch}"
    
    echo "=== Packaging ${arch} from ${bin_path} ==="
    cp "${bin_path}" "dist/${out_name}"
    chmod +x "dist/${out_name}"
    tar -czf "dist/${out_name}-${VER}.tar.gz" -C dist "${out_name}"
    rm -f "dist/${out_name}"
}

# 1. AArch64 (ARM64)
pack_arch "aarch64-musl" "target/aarch64-unknown-linux-musl/release/tachyon-core"

# 2. ARMv7 (hardfloat)
pack_arch "armv7-musl" "target/armv7-unknown-linux-musleabihf/release/tachyon-core"

# 3. ARMv6 (softfloat)
pack_arch "armv6-musl" "target/arm-unknown-linux-musleabi/release/tachyon-core"

# 4. MIPSEL (MediaTek MT7621, ramips)
pack_arch "mipsel-musl" "target/mipsel-unknown-linux-musl/release/tachyon-core"

# 5. MIPS (Qualcomm Atheros ath79)
pack_arch "mips-musl" "target/mips-unknown-linux-musl/release/tachyon-core"

# 6. x86_64 musl (OpenWrt x86, Proxmox, mini-PCs)
pack_arch "x86_64-musl" "target/x86_64-unknown-linux-musl/release/tachyon-core"

# 7. Linux amd64 (glibc Desktop/Server)
pack_arch "linux-amd64" "target/x86_64-unknown-linux-gnu/release/tachyon-core"

echo "=== Done with Linux/Router architectures ==="
ls -lh dist/
