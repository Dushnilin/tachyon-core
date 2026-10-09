#!/usr/bin/env bash
# scripts/size.sh — verifies binary size budgets for tachyon-core (full <= 12 MiB, lite <= 6 MiB).
set -euo pipefail

TARGET_DIR="${CARGO_TARGET_DIR:-target}"
TARGET_TRIPLE="${TARGET_TRIPLE:-x86_64-unknown-linux-musl}"

FULL_LIMIT=12582912    # 12 MiB
LITE_LIMIT=6291456     # 6 MiB

echo "=== Building tachyon-core (full release) ==="
cargo build --workspace --release --target "$TARGET_TRIPLE"
FULL_BIN="$TARGET_DIR/$TARGET_TRIPLE/release/tachyon-core"

if [[ ! -f "$FULL_BIN" ]]; then
    # fallback to root target if not in subfolder
    FULL_BIN="$TARGET_DIR/release/tachyon-core"
fi

FULL_SIZE=$(stat -c%s "$FULL_BIN" 2>/dev/null || stat -f%z "$FULL_BIN" 2>/dev/null || wc -c < "$FULL_BIN")

echo "=== Building tachyon-core (lite profile) ==="
cargo build -p core-cli --profile lite --target "$TARGET_TRIPLE" --no-default-features --features lite
LITE_BIN="$TARGET_DIR/$TARGET_TRIPLE/lite/tachyon-core"

if [[ ! -f "$LITE_BIN" ]]; then
    LITE_BIN="$TARGET_DIR/lite/tachyon-core"
fi

LITE_SIZE=$(stat -c%s "$LITE_BIN" 2>/dev/null || stat -f%z "$LITE_BIN" 2>/dev/null || wc -c < "$LITE_BIN")

FULL_MIB=$(awk "BEGIN {printf \"%.2f\", $FULL_SIZE / 1048576}")
LITE_MIB=$(awk "BEGIN {printf \"%.2f\", $LITE_SIZE / 1048576}")

echo ""
echo "================================================================="
echo "                TACHYON-CORE BINARY SIZE REPORT                 "
echo "================================================================="
printf "| %-12s | %-12s | %-10s | %-10s | %-8s |\n" "Build" "Bytes" "Size (MiB)" "Budget" "Status"
echo "|--------------|--------------|------------|------------|----------|"
FULL_STATUS="PASS"
if [[ "$FULL_SIZE" -gt "$FULL_LIMIT" ]]; then
    FULL_STATUS="FAIL"
fi
printf "| %-12s | %-12d | %-10s | %-10s | %-8s |\n" "full" "$FULL_SIZE" "${FULL_MIB}M" "<= 12.00M" "$FULL_STATUS"

LITE_STATUS="PASS"
if [[ "$LITE_SIZE" -gt "$LITE_LIMIT" ]]; then
    LITE_STATUS="FAIL"
fi
printf "| %-12s | %-12d | %-10s | %-10s | %-8s |\n" "lite" "$LITE_SIZE" "${LITE_MIB}M" "<= 6.00M" "$LITE_STATUS"
echo "================================================================="
echo ""

if [[ "$FULL_STATUS" == "FAIL" ]]; then
    echo "ERROR: full binary size ($FULL_SIZE bytes) exceeds 12 MiB budget!" >&2
    exit 1
fi

if [[ "$LITE_STATUS" == "FAIL" ]]; then
    echo "ERROR: lite binary size ($LITE_SIZE bytes) exceeds 6 MiB budget!" >&2
    exit 1
fi

echo "Size gate check PASSED: both full and lite builds are within limits."
