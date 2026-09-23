# Golden configuration corpus

Valid configurations must pass `tachyon-core check` **and** the reference
`sing-box-lx check` (exit code 0). Files under `invalid/` are valid JSON with
semantic errors: the reference must reject them; `tachyon-core` must reject
them too once semantic validation lands (F1) — until then the differential
harness reports them as known gaps unless `STRICT=1`.

Sources:

| Dir | Source |
|---|---|
| `lx/` | `Leadaxe/sing-box-lx` → `lx-test/config/` (XHTTP, AWG2/3, chain) |
| `tachyon/` | shape of configs emitted by Tachyon `generator.uc` |
| `invalid/` | semantic-failure cases ported from `lx-test/initerr` |

Upstream `SagerNet/sing-box` keeps its test configs inline in Go sources
(`test/box_test.go`, …), so there is no upstream JSON corpus to import;
equivalent cases get ported to `tachyon/` / `invalid/` as they are written.
