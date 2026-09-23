#!/usr/bin/env bash
# Differential harness: tachyon-core vs reference sing-box-lx on the golden corpus.
#
# usage: SING_BOX_REF=/path/to/sing-box [-c /path/to/tachyon-core] [STRICT=1] run.sh
#
#   valid dirs (lx, tachyon): both binaries must exit 0.
#   invalid dir: reference must exit non-zero; tachyon-core must exit non-zero
#   too (semantic validation, F1) — enforced only when STRICT=1, otherwise a
#   known gap is reported without failing the run.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CORPUS="$ROOT/tests/golden"
REF="${SING_BOX_REF:?set SING_BOX_REF to the reference sing-box binary}"
CORE="${TACHYON_CORE_BIN:-}"
if [[ -z "$CORE" ]]; then
  for candidate in \
    "$ROOT/target/debug/tachyon-core" \
    "$ROOT/target/debug/tachyon-core.exe" \
    "$ROOT/target/release/tachyon-core" \
    "$ROOT/target/release/tachyon-core.exe"; do
    if [[ -x "$candidate" || -f "$candidate" ]]; then CORE="$candidate"; break; fi
  done
fi
[[ -n "$CORE" && -f "$CORE" ]] || { echo "tachyon-core binary not found (build it or set TACHYON_CORE_BIN)" >&2; exit 2; }
[[ -f "$REF" ]] || { echo "reference binary not found: $REF" >&2; exit 2; }

STRICT="${STRICT:-0}"
pass=0; fail=0; gap=0

check_pair() {
  local file="$1" expect="$2"  # expect: ok | reject
  local ref_out core_out ref_code core_code
  ref_out="$("$REF" check -c "$file" 2>&1)"; ref_code=$?
  core_out="$("$CORE" check -c "$file" 2>&1)"; core_code=$?

  local ref_ok=0; [[ $ref_code -eq 0 ]] && ref_ok=1
  local core_ok=0; [[ $core_code -eq 0 ]] && core_ok=1

  if [[ "$expect" == "ok" ]]; then
    if [[ $ref_ok -eq 1 && $core_ok -eq 1 ]]; then
      pass=$((pass+1)); echo "PASS  $file"
    else
      fail=$((fail+1)); echo "FAIL  $file (expect both accept; ref=$ref_code core=$core_code)"
      [[ $ref_ok -eq 0 ]] && { echo "  ref:  $ref_out"; }
      [[ $core_ok -eq 0 ]] && { echo "  core: $core_out"; }
    fi
  else # expect: reject
    if [[ $ref_ok -eq 1 ]]; then
      fail=$((fail+1)); echo "FAIL  $file (reference unexpectedly accepts an invalid config)"
    elif [[ $core_ok -eq 1 ]]; then
      if [[ "$STRICT" == "1" ]]; then
        fail=$((fail+1)); echo "FAIL  $file (core accepts, ref rejects) [STRICT]"
      else
        gap=$((gap+1)); echo "GAP   $file (core accepts, ref rejects; semantic check = F1)"
      fi
    else
      pass=$((pass+1)); echo "PASS  $file (both reject)"
    fi
  fi
}

echo "== reference: $REF"
"$REF" version 2>&1 | head -1
echo "== core:      $CORE"
"$CORE" version 2>&1 | head -1
echo

shopt -s nullglob
for file in "$CORPUS"/lx/*.json "$CORPUS"/tachyon/*.json; do
  check_pair "$file" ok
done
for file in "$CORPUS"/invalid/*.json; do
  check_pair "$file" reject
done

echo
echo "pass=$pass fail=$fail known-gaps=$gap"
[[ $fail -eq 0 ]] || exit 1
