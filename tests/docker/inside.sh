#!/usr/bin/env bash
# Full test gate, executed inside the container (Linux).
set -euo pipefail

cd /src
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/cache/target}"
export TACHYON_CORE_BIN="$CARGO_TARGET_DIR/debug/tachyon-core"
export SING_BOX_REF="${SING_BOX_REF:-/usr/local/bin/sing-box-ref}"
# The target dir is a persistent volume, so cargo keeps every artifact of every
# past commit: a few dozen runs and it reaches tens of GB. Incremental data is
# worthless here (tests always rebuild) and stale outputs are never reused, so
# the cache is trimmed when it outgrows the budget below.
export CARGO_INCREMENTAL=0
TARGET_BUDGET_MB="${TARGET_BUDGET_MB:-8192}"

trim_target() {
    local size_mb
    size_mb="$(du -sm "$CARGO_TARGET_DIR" 2>/dev/null | cut -f1 || echo 0)"
    if [[ "$size_mb" -gt "$TARGET_BUDGET_MB" ]]; then
        echo "== target cache ${size_mb} MB > ${TARGET_BUDGET_MB} MB: cleaning"
        # the dir is a volume mount point, so cargo clean cannot remove it;
        # emptying the contents is what actually frees the host disk
        find "$CARGO_TARGET_DIR" -mindepth 1 -delete
    fi
}

# `set -e` leaves on the first failing step, so a red gate used to skip the
# trim at the bottom and the volume only ever grew; EXIT runs on both outcomes.
trap trim_target EXIT

echo "== target cache budget"
trim_target

echo "== rustfmt"
cargo fmt --all -- --check

echo "== clippy"
cargo clippy --workspace --all-targets -- -D warnings

echo "== tests"
cargo test --workspace

echo "== no-C-crypto gate (ring/aws-lc/openssl must never compile)"
c_artifacts="$(find "$CARGO_TARGET_DIR" \( -name 'libring-*' -o -name 'libaws_lc*' -o -name 'libopenssl_sys-*' \) -print 2>/dev/null || true)"
if [[ -n "$c_artifacts" ]]; then
    echo "C crypto artifacts found in target dir:" >&2
    echo "$c_artifacts" >&2
    exit 1
fi

echo "== musl static build + size budget (<= 12 MiB)"
cargo build --workspace --release --target x86_64-unknown-linux-musl
size=$(stat -c%s "$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/tachyon-core")
echo "size=$size bytes"
test "$size" -le 12582912
file "$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/tachyon-core"

echo "== differential vs $SING_BOX_REF (STRICT=1)"
STRICT=1 bash tests/differential/run.sh

echo "ALL DOCKER TESTS PASSED"
