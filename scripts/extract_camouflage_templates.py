#!/usr/bin/env python3
"""Extract ClientHello capture templates from CamouflageTLS version tables.

Reads the per-version ``.cpp`` tables of CamouflageTLS (MIT, Stas Skokov,
https://github.com/StasSkokov/CamouflageTLS) and emits one binary fixture per
browser profile containing the first five captured ClientHello records of the
first SNI-length entry:

    [u16le record count] ( [u16le record length] [record bytes] )*

The reference client picks one of the five records at random per connection
(``GetRandomHandshakeRecord``) so the decoy hello varies its GREASE value,
ECH-GREASE length and extension order; the runtime picks one of the five the
same way.  SNI / session id / random are re-stamped at build time, so the
captured SNI length of the entry does not matter.

Usage:
    python scripts/extract_camouflage_templates.py [camouflage_tls_src] [out_dir]

Defaults: camouflage-tls checkout next to this repo's temp dir, output
``crates/core-runtime/src/outbound/fptn/reality/templates``.
"""

import re
import struct
import sys
from pathlib import Path

DEFAULT_SRC = Path(
    r"C:\Users\Dushnilin\AppData\Local\Temp\opencode\camouflage-tls"
)
DEFAULT_OUT = (
    Path(__file__).resolve().parent.parent
    / "crates" / "core-runtime" / "src" / "outbound" / "fptn" / "reality" / "templates"
)

# profile name -> relative path of the version table under src/browsers
PROFILES = {
    "chrome145": "google_chrome/versions/chrome_145_0_7632_46/chrome_145_0_7632_46.cpp",
    "chrome146": "google_chrome/versions/chrome_146_0_7680_178/chrome_146_0_7680_178.cpp",
    "chrome147": "google_chrome/versions/chrome_147_0_7727_56/chrome_147_0_7727_56.cpp",
    "chrome148": "google_chrome/versions/chrome_148_0_7778_216/chrome_148_0_7778_216.cpp",
    "chrome149": "google_chrome/versions/chrome_149_0_7827_103/chrome_149_0_7827_103.cpp",
    "firefox149": "firefox/versions/firefox_149_0/firefox_149_0.cpp",
    "firefox150": "firefox/versions/firefox_150_0_3/firefox_150_0_3.cpp",
    "firefox151": "firefox/versions/firefox_151_0_3/firefox_151_0_3.cpp",
    "safari26_4": "safari/versions/safari_26_4/safari_26_4.cpp",
    "safari26_5": "safari/versions/safari_26_5/safari_26_5.cpp",
    "yandex24": "yandex_browser/versions/yandex_24_12_0_1772/yandex_24_12_0_1772.cpp",
    "yandex25": "yandex_browser/versions/yandex_25_8_3_828/yandex_25_8_3_828.cpp",
    "yandex26_3": "yandex_browser/versions/yandex_26_3_3_881/yandex_26_3_3_881.cpp",
    "yandex26_4": "yandex_browser/versions/yandex_26_4_3_897/yandex_26_4_3_897.cpp",
}

RECORDS_PER_PROFILE = 5
PACKET_RE = re.compile(
    r"\.handshake_packet\s*=\s*\{([^}]*)\}\s*,\s*\.handshake_packet_size\s*=\s*(\d+)"
)
ENTRY_RE = re.compile(r"\.sni_length\s*=\s*(\d+)\s*,\s*\.record_count\s*=\s*(\d+)")
HEX_RE = re.compile(r"0x([0-9a-fA-F]{1,2})")


def parse_hex_array(body: str) -> bytes:
    return bytes(int(h, 16) for h in HEX_RE.findall(body))


def check_record(rec: bytes) -> None:
    if len(rec) < 5 or rec[0] != 0x16:
        raise ValueError(f"not a handshake record: {rec[:8].hex()}")
    rec_len = int.from_bytes(rec[3:5], "big")
    if len(rec) < 5 + rec_len:
        raise ValueError(
            f"short record: have {len(rec)}, header claims {5 + rec_len}"
        )
    if rec[5] != 0x01:
        raise ValueError("record does not carry a ClientHello")


def extract(path: Path) -> tuple[bytes, list[int], int]:
    text = path.read_text(encoding="utf-8", errors="strict")
    entries = [(int(m.group(1)), int(m.group(2))) for m in ENTRY_RE.finditer(text)]
    if not entries:
        raise ValueError(f"{path.name}: no entries parsed")

    packets: list[bytes] = []
    for m in PACKET_RE.finditer(text):
        body, declared = m.group(1), int(m.group(2))
        # The tables spell out the full fixed handshake_packet[2048] capacity;
        # handshake_packet_size is the real length, the tail is zero padding.
        padded = parse_hex_array(body)
        if len(padded) < declared or any(padded[declared:]):
            raise ValueError(
                f"{path.name}: bad padding: {len(padded)} bytes, "
                f"declared {declared}"
            )
        rec = padded[:declared]
        check_record(rec)
        packets.append(rec)
        if len(packets) == RECORDS_PER_PROFILE:
            break
    if len(packets) < RECORDS_PER_PROFILE:
        raise ValueError(
            f"{path.name}: wanted {RECORDS_PER_PROFILE} records, got {len(packets)}"
        )

    out = bytearray(struct.pack("<H", len(packets)))
    for rec in packets:
        out += struct.pack("<H", len(rec))
        out += rec
    sni_lengths = sorted({e[0] for e in entries})
    return bytes(out), sni_lengths, entries[0][1]


def main() -> int:
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_SRC
    out_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_OUT
    out_dir.mkdir(parents=True, exist_ok=True)

    total = 0
    for profile, rel in PROFILES.items():
        path = src / "src" / "browsers" / rel
        blob, sni_lengths, records = extract(path)
        (out_dir / f"{profile}.bin").write_bytes(blob)
        total += len(blob)
        print(
            f"{profile:12} {len(blob):6} B  entries sni={sni_lengths[0]}..{sni_lengths[-1]}"
            f" ({len(sni_lengths)})  records/entry={records}"
        )
    print(f"total {total} B -> {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
