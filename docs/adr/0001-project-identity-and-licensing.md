# ADR 0001: Project identity and licensing

Date: 2026-09-23

## Context

`tachyon-core` is a Rust reimplementation of the sing-box client core with the
Leadaxe/sing-box-lx feature set. It consumes the same JSON configuration, exposes
the same CLI, and is intended as a router-friendly drop-in replacement
(ultimately a Tachyon engine variant).

## Decision

- License the project **GPL-3.0-only**, inherited from sing-box / sing-box-lx.
  Translating their code, porting their tests, and reusing their spec corpus are
  derivative works; GPL-3.0 keeps this unambiguous.
- Distribute binaries under the same license with source availability.
- Keep an explicit compatibility contract: when `argv[0]` is `sing-box`, print
  upstream-shaped `sing-box version X.Y.Z-…` output so existing orchestration
  regexes (Tachyon `generator.uc`) keep matching.

## Consequences

- Every derived file carries GPL-3.0 headers via the workspace `LICENSE`.
- No permissive-licensed vendored code without license review.
