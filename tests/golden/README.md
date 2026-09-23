# Golden configuration corpus

Drop sing-box / sing-box-lx test configs and Tachyon-generated fixtures here
(file name → one config per file). Used by `tests/differential`:

1. `tachyon-core check -c <file>` vs `sing-box check -c <file>` — same exit code.
2. Run-time smoke: `tachyon-core run` on configs marked `smoke: true`.

Sources:
- `Leadaxe/sing-box-lx` → `lx-test/config/`
- `SagerNet/sing-box` → `cmd/sing-box/testdata/`
- Tachyon `tests/` fixtures
