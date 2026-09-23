#!/usr/bin/env bash
# Full test gate, executed inside the container (Linux).
set -euo pipefail

cd /src
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/cache/target}"
export TACHYON_CORE_BIN="$CARGO_TARGET_DIR/debug/tachyon-core"
export SING_BOX_REF="${SING_BOX_REF:-/usr/local/bin/sing-box-ref}"

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
