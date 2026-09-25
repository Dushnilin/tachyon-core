//! MASQUE (Cloudflare WARP) CONNECT-IP outbound.
//!
//! Ports the reference sing-box-lx `protocol/masque` behavior: profiles
//! (cloudflare/standard), h3/h2/vhttp-auto legs, in-process smoltcp stack,
//! CONNECT-IP capsules with TTL/checksum translation and ICMP too-big.
//!
//! Protocol layers live in submodules: h3 (minimal HTTP/3 client),
//! h2 (manual framer), qpack / hpack (header block codecs),
//! connectip (capsules + packet rewrite), tls (pinning + mTLS),
//! huffman / static_tables (generated RFC tables).

#![allow(dead_code)]

mod connectip;
mod hpack;
mod huffman;
mod p256;
mod qpack;
mod static_tables;
