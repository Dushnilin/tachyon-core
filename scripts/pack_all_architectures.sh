#!/usr/bin/env bash
set -euo pipefail

cd /src
mkdir -p dist
rm -rf dist/*
VER="${1:-v0.0.2}"

pack_arch() {
    local arch="$1"
    local bin_path="$2"
    local out_name="tachyon-core-${arch}"
    
    if [ ! -f "${bin_path}" ]; then
        echo "=== Skipping ${arch}: ${bin_path} not found ==="
        return 0
    fi

    echo "=== Packaging ${arch} from ${bin_path} ==="
    cp "${bin_path}" "dist/${out_name}"
    chmod +x "dist/${out_name}"
    tar -czf "dist/${out_name}-${VER}.tar.gz" -C dist "${out_name}"
    
    local arch_short="${arch%-musl}"
    if [ "${arch_short}" != "${arch}" ]; then
        cp "dist/${out_name}-${VER}.tar.gz" "dist/tachyon-core-${arch_short}-${VER}.tar.gz"
    fi

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

if [ -d "openwrt" ]; then
    echo "=== Packaging OpenWrt Package Archive ==="
    tar -czf "dist/tachyon-core-openwrt-package-${VER}.tar.gz" openwrt/
fi

cd dist
sha256sum *.tar.gz > SHA256SUMS
cat SHA256SUMS

echo "=== Done with Linux/Router architectures ==="
ls -lh
