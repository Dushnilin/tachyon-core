# ADR 0004: uTLS-style fingerprints and REALITY client

Date: 2026-09-23

## Context

Parity with sing-box-lx requires:

- TLS ClientHello fingerprints (`tls.utls.fingerprint`: chrome, firefox,
  safari, …), including hybrid `X25519MLKEM768` key share (`key_share:
  classical | hybrid`) that current Xray servers demand;
- the REALITY client handshake (custom key share, `short_id`, auth,
  ClientHello fragmentation / `record_fragment`).

There is no maintained 1:1 port of refraction-networking/utls to Rust; the
ecosystem splits between CGO/C-backed impersonation clients (bad for MIPS,
defeats the static-musl goal) and pure-Rust Hello builders.

## Decision

- **Pure-Rust ClientHello builder**: assemble the TLS 1.3 ClientHello
  ourselves (byte-level control over extension order and key_share) with
  presets vendored from the sing-box-lx/utls-lx fingerprint tables
  (GPL-3.0 compatible: this project is GPL-3.0).
- **Hybrid post-quantum share** via the pure-Rust `ml_kem` crate composed
  with `x25519-dalek` (X25519MLKEM768 = ML-KEM-768 share prepended, as
  Xray/utls encode it).
- **REALITY client** implemented as an explicit handshake over our Hello
  builder + rustls for the established session (server auth via the
  reality public key, `short_id` match, then transparent splice).
- Rejected: `tls-client`/boring-based impersonation (pulls C, no MIPS),
  wrapping a bundled utls fork through FFI (build complexity, flash cost).

## Consequences

- F0 spike exit criterion: fingerprint bytes for at least `chrome` match the
  reference on a captured ClientHello diff, and a REALITY handshake completes
  against a live Xray ≥ v26.9.9 test server (tracked as F2 verification too).
- Fragmentation (`fragment`, `record_fragment`) is implemented on the same
  layer, so REALITY fragmentation support comes for free (leadaxe feature 017).
- Preset table maintenance: synced from upstream tables when fingerprints
  drift; divergence noted in COMPAT.md.

## Spike outcome (F0, 2026-09-23)

- Captured a real utls `chrome` ClientHello from sing-box-lx v1.14.1-lx.8:
  local socks inbound → vless outbound (utls chrome) → TCP sink
  (`tests/spikes/clienthello/run.sh`, fixture `chrome_lx8.bin`, 1789 bytes).
- Modern chrome fingerprint observed: hybrid X25519MLKEM768 key share
  (group `0x11ec`) plus a GREASE key share entry, GREASE ciphers, ALPN
  `h2,http/1.1`, SNI `www.gstatic.com`.
- `core-tls::hello` implements a byte-level parser + builder: the rebuilt
  hello matches the capture **byte-for-byte** when fed the same
  random/session_id/SNI and reuses the template key share; with fresh
  randomness it differs only in random/session/key fields while preserving
  cipher list and extension order (tests in `crates/core-tls/tests/chrome_hello.rs`,
  green in the Docker gate).
- Template extraction from a capture is the spike path; production presets
  will be vendored as static tables from utls-lx fingerprint sources (F2),
  with this byte-diff harness as the verification method.
- REALITY live handshake against Xray remains an F2 verification item.

## Fingerprint tables (F2, 2026-09-30)

- `tests/spikes/clienthello/capture_fingerprints.sh` runs the *reference* as a
  uTLS client against a sink and writes its first record, once per
  fingerprint. `tools/fingerprint_tables.py` turns those captures into
  `crates/core-tls/src/fingerprints.rs`: a fingerprint is a cipher list, an
  extension order and the bodies of the extensions that do not change per
  connection. `Ext::KeyShare` keeps the captured body, so the modern Chrome
  table still offers X25519MLKEM768 (SPEC 083/089).
- `crates/core-tls/tests/fingerprints.rs` rebuilds every table and compares it
  with the capture it came from, ignoring only what the reference itself
  randomizes per handshake: GREASE values, the `random` field, and the session
  id *content* (its length is the claim — REALITY seals its auth key into 32
  bytes of it).
- **The reference is not byte-stable either.** `HelloChrome_Auto` picks a Chrome
  version per handshake: three connections from one process produced three
  different hellos (`tests/spikes/clienthello/chrome_stability.sh`, three
  distinct md5s). So the exit criterion "the fingerprint bytes match the
  reference" has to mean *structurally*, per version — which is what the table
  test checks. A vendored table is one stable Chrome version, which is what
  REALITY deployments use in practice.
- No rustls fork is needed, and none is planned: the ClientHello is ours, and
  the handshake on top of it uses the pure-Rust crypto provider (`core-crypto`)
  and `rustls-webpki` for chain verification. Both are already in the tree, and
  neither is a fork.

## Key schedule and the REALITY wire details (F2, 2026-09-30)

- `core-tls/src/tls13.rs` is the TLS 1.3 key schedule (RFC 8446 §7.1): HKDF
  over SHA-256/384, `Expand-Label`, the traffic keys, and the per-record nonce.
  Its test reproduces **every** intermediate value RFC 8448 §3 prints for the
  simple 1-RTT handshake, so a mistake shows up at the step it was made. The
  schedule takes a transcript *hash*, not the messages: the handshake layer
  keeps the running hash anyway, and the RFC prints hashes.
- Two details the first implementation got wrong, both caught by the vectors
  rather than by a handshake failing: an absent PSK is the all-zero IKM of the
  hash length (not an empty message), and a literal with an odd number of hex
  digits shifts every byte after it. The test helper now checks its own
  literals for even length.
- The REALITY client details come from `XTLS/Xray-core`
  `transport/internet/reality/reality.go`, which is what the servers implement:
  * `session_id` is 32 bytes: `[0..3]` the version triple, `[3]` zero,
    `[4..8]` the unix time, `[8..16]` the short id; the first 16 bytes are then
    AES-256-GCM sealed with the **whole ClientHello as AAD** and
    `random[20..32]` as the nonce, and the 32-byte result is written back at
    the fixed offset 39 (4 + 2 + 32 + 1).
  * the auth key is the X25519 (or the X25519 half of X25519MLKEM768) shared
    secret with the server key, run through `HKDF-SHA256(salt=random[:20],
    info="REALITY")`.
  * the server is trusted when the leaf's Ed25519 public key HMAC-SHA512's
    under that auth key to the leaf's own signature, with a normal chain
    verification as the fallback.
- The fork at `GFW-knocker/Xray-core` states the fingerprint shortlist in
  `infra/conf/reality_fingerprint_test.go`: `ios`, `edge`, `qq`, `android` and
  `360` are replaced with `chrome` there, because a current REALITY server
  cannot verify those hellos. **The lx reference does not do that** — it sends
  the small hello as configured (measured: 517 bytes for `ios`/`edge`/`qq`
  against 1789 for `chrome`, both with and without `reality`), so our captures
  and tables serve the REALITY path unchanged and no substitution is made.

## The key share we put our own keys into (F2, 2026-09-30)

`core-tls/src/keyshare.rs`. The table supplies the *group list*; the share data
is generated per handshake, because a captured key cannot complete an exchange.
The layout was measured from the captures and read out of
`refraction-networking/utls` `key_schedule.go`:

| | group | bytes | contents |
|---|---|---|---|
| client share | `0x11ec` X25519MLKEM768 | 1216 | ML-KEM-768 **encapsulation key** (1184) ‖ X25519 (32) |
| server share | `0x11ec` | 1120 | ML-KEM-768 **ciphertext** (1088) ‖ X25519 (32) |
| shared secret | `0x11ec` | 64 | ML-KEM secret ‖ X25519 secret, in that order |

The 1216 was the number to get right: it is not the 1120 the draft's arithmetic
suggests, because the client sends the 1184-byte *encapsulation key*, not the
1088-byte ciphertext, and a server that assumed otherwise would reject every
hello. A test encapsulates against the very key the client offered and checks
the secret comes out as `ML-KEM ‖ X25519`, so a swapped pair of halves fails
there.

Two details that are fingerprints in their own right:

- Chrome and Firefox offer a **second, plain X25519 share** next to the hybrid,
  and it is a *different* key from the hybrid's X25519 half — utls generates a
  separate one "in line with Chrome" (`keySharePrivateKeys.mlkemEcdhe`). We do
  the same; a client that reuses one key for both is not a browser.
- Firefox also offers a `secp256r1` share (a 65-byte uncompressed point), so we
  generate one too (`p256`, pure Rust) rather than offer a key we hold no
  private half of. A group we cannot answer is an error at build time, never a
  silent fallback.

**GREASE is now drawn per handshake**, both for extension ids and for the
GREASE key share group, as BoringSSL does. A constant GREASE value across
connections is a signature in itself, and it is the one byte range where the
reference already differs from itself. The cost is that no hello can be
byte-identical to a capture any more: the rebuild tests are structural, exactly
like the table test above.

