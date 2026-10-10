"""Turn the captured ClientHellos into the vendored fingerprint tables.

The captures live in tests/spikes/clienthello/captures/*.bin (one handshake
record each, written by the reference running as a uTLS client). What a
fingerprint *is* is a byte template: the cipher list, the extension order and
the extension bodies, with the three fields that change per connection (random,
session id, key share) left to the builder.

Emits crates/core-tls/src/fingerprints.rs, and each table is checked against
its own capture by tests/fingerprints.rs.
"""

import io
import json
import os
import struct
import sys

SRC = "tests/spikes/clienthello/captures"
DST = "crates/core-tls/src/fingerprints.rs"

# extensions whose body carries the SNI, the ALPN or the key share: the builder
# fills those in, so the table stores an empty body and the kind
DYNAMIC = {0x0000: "Sni", 0x0010: "Alpn", 0x0033: "KeyShare"}


def u16(data, off):
    return struct.unpack_from(">H", data, off)[0], off + 2


def parse(data):
    if data[0] != 0x16:
        raise SystemExit("not a handshake record")
    rec_ver = (data[1], data[2])
    body = data[5 : 5 + u16(data, 3)[0]]
    if body[0] != 0x01:
        raise SystemExit("not a ClientHello")
    off = 4
    client_version = tuple(body[off : off + 2])
    off += 2
    random = body[off : off + 32]
    off += 32
    sid_len = body[off]
    off += 1
    session_id = body[off : off + sid_len]
    off += sid_len
    cipher_len, off = u16(body, off)
    ciphers = body[off : off + cipher_len]
    off += cipher_len
    comp_len = body[off]
    off += 1
    compression = body[off : off + comp_len]
    off += comp_len
    ext_total, off = u16(body, off)
    end = off + ext_total
    exts = []
    while off < end:
        ext_id, off = u16(body, off)
        ext_len, off = u16(body, off)
        ext_body = body[off : off + ext_len]
        off += ext_len
        exts.append((ext_id, ext_body))
    return {
        "record_version": rec_ver,
        "client_version": client_version,
        "random": random,
        "session_id": session_id,
        "ciphers": ciphers,
        "compression": compression,
        "extensions": exts,
    }


def is_grease(value):
    return value & 0x0F0F == 0x0A0A and (value >> 8) == (value & 0xFF)


def vec_bytes(raw):
    return "vec![" + ", ".join("0x%02x" % byte for byte in raw) + "]"


def emit(name, parsed):
    ext_lines = []
    for ext_id, body in parsed["extensions"]:
        kind = DYNAMIC.get(ext_id)
        if kind:
            if kind == "KeyShare":
                # the captured body is kept: a modern hello offers the hybrid
                # share, and the builder swaps in our own key when asked
                ext_lines.append(
                    "        Ext::KeyShare(%s)," % vec_bytes(body)
                )
            else:
                ext_lines.append("        Ext::%s," % kind)
            continue
        ext_lines.append("        Ext::Static(0x%04x, %s)," % (ext_id, vec_bytes(body)))
    ciphers = parsed["ciphers"]
    pairs = []
    for i in range(0, len(ciphers), 2):
        pair = struct.unpack_from(">H", ciphers, i)[0]
        pairs.append("0x%04x" % pair)
    ident = ("r" + name) if name[0].isdigit() else name
    return """/// Captured from sing-box-lx %s running as a uTLS client
/// (tests/spikes/clienthello/captures/%s.bin, %d bytes).
pub fn %s() -> Template {
    Template {
        record_version: [%d, %d],
        client_version: [%d, %d],
        cipher_suites: vec![
            %s,
        ],
        compression: vec![
            %s,
        ],
        extensions: vec![
%s
        ],
    }
}
""" % (
        VERSION,
        name,
        os.path.getsize(os.path.join(SRC, name + ".bin")),
        ident,
        parsed["record_version"][0],
        parsed["record_version"][1],
        parsed["client_version"][0],
        parsed["client_version"][1],
        ", ".join("0x%02x" % byte for byte in ciphers),
        ", ".join("0x%02x" % b for b in parsed["compression"]),
        "\n".join(ext_lines),
    )


VERSION = sys.argv[1] if len(sys.argv) > 1 else "1.14.2-lx.3"

names = sorted(
    f[:-4] for f in os.listdir(SRC) if f.endswith(".bin")
)
if not names:
    raise SystemExit("no captures in " + SRC)

body = []
for name in names:
    with open(os.path.join(SRC, name + ".bin"), "rb") as fh:
        body.append(emit(name, parse(fh.read())))

# Sing-Box X's modern profiles override the historical upstream captures.
# Keep the other profiles' original provenance and byte tables.
old_src, old_version = SRC, VERSION
SRC = "tests/spikes/clienthello/captures-sing-box-x"
VERSION = "1.14.2-x-1.0.3"
for name in ["chrome", "firefox", "safari"]:
    with open(os.path.join(SRC, name + ".bin"), "rb") as fh:
        generated = emit(name, parse(fh.read())).replace(
            "Captured from sing-box-lx", "Captured from Sing-Box X"
        ).replace("tests/spikes/clienthello/captures/", SRC + "/")
    if name in names:
        body[names.index(name)] = generated
    else:
        body.append(generated)
SRC, VERSION = old_src, old_version

HEADER = '''//! The uTLS fingerprint tables, vendored from the reference's captures.
//!
//! A fingerprint is data, not code: which ciphers, which extensions in which
//! order, and the bodies of the ones that do not change per connection. The
//! three fields that do -- `random`, the session id and the key share -- are
//! filled in by `hello::build`, and the session id is what REALITY seals its
//! auth key into.
//!
//! `Ext::KeyShare` keeps its captured body here, hybrid share included, so a
//! modern Chrome hello keeps offering X25519MLKEM768 the way the reference
//! does (SPEC 083).
//!
//! Generated by tests/spikes/clienthello/capture_fingerprints.sh plus
//! tools/fingerprint_tables.py; checked byte-for-byte by
//! crates/core-tls/tests/fingerprints.rs.

use super::hello::{Ext, Template};

/// The reference build the tables were captured from.
pub const CAPTURED_FROM: &str = "@VERSION@";
/// Modern Chrome/Firefox/Safari come from our X build.
pub const MODERN_CAPTURED_FROM: &str = "1.14.2-x-1.0.3";

/// Every fingerprint name the reference accepts, and the table behind it. The
/// six `chrome_*` names all resolve to the same `HelloChrome_Auto` in the
/// reference (common/tls/utls_client.go). Random policies are resolved once per
/// process by `random_fingerprints`, separately from the captured tables.
pub fn by_name(name: &str) -> Option<Template> {
    Some(match name {
        "" | "chrome" | "chrome_psk" | "chrome_psk_shuffle"
        | "chrome_padding_psk_shuffle" | "chrome_pq" | "chrome_pq_psk" => chrome(),
        "firefox" => firefox(),
        "edge" => edge(),
        "safari" => safari(),
        "360" => r360(),
        "qq" => qq(),
        "ios" => ios(),
        "android" => android(),
        "random" => super::random_fingerprints::random(),
        "randomized" => super::random_fingerprints::randomized(),
        _ => return None,
    })
}

/// The names the reference maps to a table, for `check` and for the docs.
pub const NAMES: &[&str] = &[
    "chrome_psk", "chrome_psk_shuffle", "chrome_padding_psk_shuffle", "chrome_pq",
    "chrome_pq_psk", "chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android",
    "random", "randomized",
];

'''

out = HEADER.replace("@VERSION@", VERSION) + "\n".join(body) + "\n"

with io.open(DST, "w", encoding="utf-8", newline="\n") as fh:
    fh.write(out)
print("wrote", DST, "with", len(names), "tables")
