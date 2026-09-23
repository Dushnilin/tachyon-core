# ADR 0005: bbolt-compatible `cache.db`

Date: 2026-09-23

## Context

sing-box persists `experimental.cache_file` (FakeIP mappings, DNS cache) in a
bbolt database (`store_fakeip`, `store_dns`, and pre-1.14 `store_rdrc`).
Tachyon clears `/tmp/sing-box/cache.db` (and the turbo-cache copy under
`/etc/sing-box/`) on quick-fix, but users may carry an existing file across an
engine switch, and 1.14+ tunes `buffer_size` / `flush_interval` — the
compatibility promise says files must interoperate, not just coexist.

bbolt is a single-file B+tree with 4 KiB pages, two meta pages and a
freelist; the format is stable and documented in the Go source.

## Decision

- Implement a **minimal bbolt subset** in `core-experimental`:
  read buckets/keys from a file written by Go bbolt (including files written
  by the reference sing-box), and write back in the same format.
- **Atomic full rewrite on flush** (tmp + fsync + rename) instead of in-place
  page updates: the dataset is small (FakeIP + DNS cache), flash wear and
  corruption risk on power loss matter more than incremental page reuse.
- No mmap and no freelist reuse — we only need correct page/B+tree layout
  and checksums; freelist pages are written as "no free pages".
- Single-process ownership (the core owns the file while running), so no
  cross-process locking beyond what bbolt's file lock already provides;
  we take the exclusive flock exactly like upstream.

## Consequences

- Interop test in the differential harness: run reference sing-box to produce
  a `cache.db`, read it with `core-experimental`, write it back, re-open with
  the reference (`check`/API dump or Go bbolt CLI in CI) — round-trip must
  succeed (F4 gate).
- Divergences to document in COMPAT.md: page-fill heuristics, no freelist
  compaction, unknown top-level buckets preserved as opaque blobs (forward
  compatibility with upstream additions).
- If upstream ever switches storage engine, this crate is isolated behind the
  `cache_file` interface and gets replaced, not rewritten across the core.

## Spike outcome (F0, 2026-09-23)

- Format facts validated against go.etcd.io/bbolt v1.5.0 source:
  magic `0xED0CDAED`, version `2`, meta = page header (16B) + 64B body,
  checksum = FNV-1a-64 over body[0..56), page `id` = `txid % 2`,
  active meta = highest valid txid, `freelist = u64::MAX` means
  "no persisted freelist", leaf element `pos` is relative to the element
  (not the page), **keys must be stored sorted** (Go lookup is binary
  search), inline buckets carry `root = 0` with the page appended after the
  16B bucket header.
- `crates/core-experimental` implements the read path (leaf/branch/inline)
  and a single-page-per-node write path; round-trip proven in
  `tests/golden_roundtrip.rs`: reads the committed Go-written
  `tests/spikes/bbolt/golden.db`, and its own output is verified by
  `tests/spikes/bbolt/gen` (`go run ./gen verify`) — both legs green in the
  Docker gate.
- Multi-page leaf overflow, freelist compaction and branch-page writing are
  out of scope for the spike; needed later for large DNS caches (F4 gate).
