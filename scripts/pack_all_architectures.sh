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
    rm -f "dist/${out_name}"
}

# 1. AArch64 musl
pack_arch "aarch64-musl" "target/aarch64-unknown-linux-musl/release/tachyon-core"

# 2. ARMv6 musl
pack_arch "armv6-musl" "target/arm-unknown-linux-musleabi/release/tachyon-core"

# 3. ARMv7 musl
pack_arch "armv7-musl" "target/armv7-unknown-linux-musleabihf/release/tachyon-core"

# 4. Linux amd64 (glibc)
pack_arch "linux-amd64" "target/x86_64-unknown-linux-gnu/release/tachyon-core"

# 5. MIPS musl
pack_arch "mips-musl" "target/mips-unknown-linux-musl/release/tachyon-core"

# 6. MIPSEL musl
pack_arch "mipsel-musl" "target/mipsel-unknown-linux-musl/release/tachyon-core"

# 7. OpenWrt Package Archive
if [ -d "openwrt" ]; then
    echo "=== Packaging OpenWrt Package Archive ==="
    tar -czf "dist/tachyon-core-openwrt-package-${VER}.tar.gz" openwrt/
fi

# 8. Windows amd64 zip
if [ -f "target/release/tachyon-core.exe" ]; then
    echo "=== Packaging Windows amd64 zip ==="
    which zip >/dev/null 2>&1 && (
        cd target/release && zip "/src/dist/tachyon-core-windows-amd64-${VER}.zip" tachyon-core.exe
    ) || true
fi

# 9. x86_64 musl
pack_arch "x86_64-musl" "target/x86_64-unknown-linux-musl/release/tachyon-core"

cd dist
rm -f SHA256SUMS
sha256sum * > SHA256SUMS
cat SHA256SUMS

echo "=== Done with Linux/Router architectures ==="
ls -lh
