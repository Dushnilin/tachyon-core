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
| `tachyon/` | shape of configs emitted by Tachyon `generator.uc`; includes `f1-exit-gate.json` (live router-main minus F2/F3 fields: hysteria2, xhttp, REALITY, rule_set rules) |
| `live/` | `router-main.json`: sanitized dump (hosts/uuids/passwords/reality keys replaced) of a live router's `/etc/sing-box/config.json` — F1 exit-gate target; uses F2/F3 fields (xhttp/grpc transports, REALITY, rule_set), so it is NOT part of the `check` corpus yet |
| `invalid/` | empirically verified rejections against sing-box-lx v1.14.2-lx.3 |

Upstream `SagerNet/sing-box` keeps its test configs inline in Go sources
(`test/box_test.go`, …), so there is no upstream JSON corpus to import;
equivalent cases get ported to `tachyon/` / `invalid/` as they are written.
