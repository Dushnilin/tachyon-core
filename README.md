# tachyon-core

**sing-box-lx compatible proxy core in Rust, built for routers.**

`tachyon-core` is a ground-up Rust implementation of the [sing-box](https://github.com/SagerNet/sing-box)
universal proxy platform with the client-side feature set of
[Leadaxe/sing-box-lx](https://github.com/Leadaxe/sing-box-lx) (XHTTP, AmneziaWG 2/3,
MASQUE/WARP, REALITY with hybrid key share, `chain`, DNS groups, sniffers, `lxd` daemon).
It consumes the **same JSON configuration** as sing-box, exposes the **same CLI surface**,
and is optimized for routers — including old devices with small flash and RAM.

> Status: **early scaffolding (F0)**. Not usable yet. See [ROADMAP.md](ROADMAP.md).

## Why

- **Drop-in compatibility**: `tachyon-core` installed as `sing-box` answers
  `sing-box version`, `check`, `run`, `rule-set`, `generate …` — existing
  orchestration (Tachyon ucode layer) keeps working without changes.
- **Router-first**: `opt-level=z`, LTO, `panic=abort`, cargo feature gates
  (`tiny` profile), target budget ≤ 12 MiB stripped (stretch ≤ 8 MiB).
- **No Go toolchain pain**: single static musl binary, cross-built in CI for
  `x86_64`/`armv7`/`aarch64`, MIPS (softfloat) lands after the core stabilizes.

## Build

```bash
cargo build --workspace --release
cargo test --workspace
```

## CLI surface (compatibility contract)

| Command | Status |
|---|---|
| `check -c <path>` | scaffold (JSON parse only) |
| `version` | scaffold (upstream-shaped when `argv[0] == sing-box`) |
| `run`, `format`, `upgrade` | planned (F1) |
| `rule-set compile\|decompile\|upgrade` | planned (F3) |
| `generate uuid\|rand\|reality-keypair\|wg-keypair\|tls-keypair` | planned (F1) |
| `api`, `dns`, `lxd` | planned (F4/F7) |

## Configuration compatibility

Full schema compatibility with sing-box is the goal — including raw JSON
outbounds passed through verbatim from subscriptions. Coverage is tracked
field by field in [COMPAT.md](COMPAT.md).

## License

[GPL-3.0-only](LICENSE) — inherited from sing-box / sing-box-lx.
This is an unofficial implementation, not affiliated with SagerNet or Leadaxe.
