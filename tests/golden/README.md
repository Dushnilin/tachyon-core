# Golden configuration corpus

Valid configurations must pass `tachyon-core check` **and** the reference
`sing-box-lx check` (exit code 0). Files under `invalid/` are valid JSON with
semantic errors: both `tachyon-core` and the reference must reject them
(semantic validation landed in F1; the differential harness enforces this
under `STRICT=1`, which CI and the Docker gate set).

Sources:

| Dir | Source |
|---|---|
| `lx/` | `Leadaxe/sing-box-lx` → `lx-test/config/` (XHTTP, AWG2/3, chain) |
| `tachyon/` | shape of configs emitted by Tachyon `generator.uc` |
| `invalid/` | empirically verified rejections against sing-box-lx v1.14.1-lx.8 |

Upstream `SagerNet/sing-box` keeps its test configs inline in Go sources
(`test/box_test.go`, …), so there is no upstream JSON corpus to import;
equivalent cases get ported to `tachyon/` / `invalid/` as they are written.
