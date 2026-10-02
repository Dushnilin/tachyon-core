# Changelog

All notable changes to tachyon-core. The version is the workspace version in
`Cargo.toml`; a tag that disagrees with it is refused by the release workflow.

## 0.0.1

The first tagged build. A routing core for OpenWrt: the client stack end to
end, plus the server half of the four TCP proxy protocols.

### What runs

- **Inbounds**: `mixed` (HTTP, SOCKS4/4a, SOCKS5 with UDP ASSOCIATE), `direct`,
  `redirect` (Linux `REDIRECT`), `tproxy` (v4/v6 with `IP_TRANSPARENT`), and the
  server inbounds `vless`, `trojan`, `vmess` and `shadowsocks`.
- **Server inbounds** accept the TCP command and the UDP command, over a `tls`
  block with our own handshake — TLS 1.3, X25519, three cipher suites, ALPN, no
  resumption, HelloRetryRequest handled the same way the client does.
- **Outbounds**: `direct`, `block`, `socks`, `http`, `shadowsocks`, `vless`,
  `vmess`, `trojan`, `hysteria2`, `tuic`, `anytls`, `naive`, `snell`, `masque`
  (warp), `fptn`, `urltest`, `selector`, and the `wireguard` and
  `openvpn-client` endpoints, WireGuard with AmneziaWG 2.0/3.x shapes included.
- **Transports**: `ws`, `httpupgrade`, `grpc`, `http`, `xhttp` with `xmux`,
  all three `packet_encoding` modes, uTLS fingerprints and REALITY.
- **DNS**: `udp`, `tcp`, `tls`, `https`, `quic`, `h3`, `fakeip`, `local`,
  `hosts`, `group` and `mdns`; logical rules, `rule_set`, hijack-DNS,
  `reverse_mapping`, `client_subnet`.
- **Routing**: the matcher set including `route.find_neighbor` for
  `source_mac_address` and `source_hostname`, sniffing, and the SRS rule-set
  reader.
- **Experimental**: `clash_api` REST with websocket streaming and the `external_ui`
  download, and a `cache.db` that Go bbolt can read.

### Measurements

Taken on 2026-10-02 with the same toolchain the release workflow uses:
`cargo build --release` against a musl target, `RUSTFLAGS="-C linker=rust-lld
-C link-self-contained=yes"`, release profile (`opt-level = "z"`, LTO,
`codegen-units = 1`, `panic = "abort"`, `strip = "symbols"`).

| | tachyon-core | sing-box-lx 1.14.2-lx.2 | |
|---|:---:|:---:|---|
| binary, aarch64 | **5.37 MiB** | 67.6 MiB | 12.6× smaller |
| binary, armv7 | **5.57 MiB** | 68.2 MiB | 12.2× smaller |
| binary, x86_64 | **6.85 MiB** | 75.9 MiB | 11.1× smaller |
| idle RSS, mixed + direct | **2.4 MiB** | 42.7 MiB | 17.8× less |

The earlier figures in this repository -- 3.5 MiB for aarch64, 19× smaller --
came from a `cargo zigbuild` run, which is not what builds the released binary,
so they were not numbers the release could reproduce. Zig is not in the release
image; `rust-lld` is. The honest numbers are the ones above, and the tree grew
into them: a full TLS 1.3 *server* stack and the server UDP path are new since
that measurement.

CI keeps a hard ceiling of 12 MiB on every architecture it builds, mipsel and
mips included, which the largest of the above clears by 43%.

### Platforms

Static musl builds for the OpenWrt targets: `x86_64`, `aarch64`, `armv7`,
`armv6`, `riscv64`, `mipsel` and `mips`. The two MIPS targets are tier-3 and
their standard library is built from source; they are built and size-checked,
but nothing in this release has been *run* under qemu-user.

The cryptography is pure Rust throughout — no `ring`, no `aws-lc-rs`, no CGO —
so the same source builds for 32-bit softfloat MIPS.

### Known gaps

Stated plainly, because a release note that hides them is worth less than one
that names them:

- No `tun` inbound, no `lxd` daemon, no libbox/Android bindings.
- No server inbound for `hysteria2`, `tuic` or WireGuard yet; the vless, trojan
  and vmess server sides do not speak mux (`packetaddr`/`xudp`), Vision's server
  splice, or the legacy vmess CFB body.
- `insecure: true` with no certificate on a server inbound is refused: it needs
  an ephemeral key pair, and nothing here can sign a certificate.
- `COMPAT.md` predates most of this work and does not describe the tree.

### Fixes worth naming

Four of these were live defects rather than missing features, and all four were
found by measuring our own client against our own server:

- vmess `security: auto` became `none` whenever the outbound had a `tls` block,
  so any TLS vmess config carried its payload unencrypted.
- The server-side TLS record layer sealed writes larger than one record, and the
  length in the header is a `u16`: a long write wrapped round to a short length
  and the client read a truncated ciphertext out of the middle of it.
- An inline `certificate`/`key` on a server inbound was read only as a string,
  where the reference reads a `Listable[string]` — the form nearly every config
  actually uses.
- The vmess UDP client consumed one byte of the server's answer instead of two,
  and read the rest as the length of the first datagram.
