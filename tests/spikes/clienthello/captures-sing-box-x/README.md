# Sing-Box X 1.0.3 ClientHello captures

Captured on loopback with `tools/capture_x_fingerprints.py` from our x86_64
Sing-Box X 1.0.3 binary, extracted from the hash-verified mirror IPK and unpacked
with UPX. `provenance.json` records the package, binary and capture hashes.
These fixtures contain generated public handshake data and a dummy VLESS UUID.

Firefox 148 and Safari 26.3 presets and the coherent randomized/REALITY behavior
originate in Sing-Box X's `patches/tls-fingerprints` series by FiyeroT from
podkop-engine v1.14.2-r12 (GPL-3.0-or-later), crediting Xray-core and
refraction-networking/utls aa6edf4. Rust X uses measured tables rather than Go code.

Chrome aliases resolve to the updated Chrome table, used for Forkop XHTTP.
Firefox and Safari are the other profiles used by this deployment.
Random profiles are outside this update; no new runtime support is added for them.
Firefox's classical X25519 share reuses the hybrid X25519 key; Chrome and Safari
use independent keys. REALITY's existing client version remains 26.3.27.

Legacy Edge/iOS/Android/360/QQ tables remain unchanged and do not gain modern
hybrid REALITY compatibility through these changes. Captured ECH GREASE payloads
remain templates; this work does not implement real ECH or TLS session resumption.

Regenerate tables with `python3 tools/fingerprint_tables.py`, then `cargo fmt`.
