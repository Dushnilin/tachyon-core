# Differential tests

`run.sh` compares `tachyon-core check` against the reference `sing-box-lx check`
on the golden corpus:

```bash
cargo build --workspace
SING_BOX_REF=/path/to/sing-box bash tests/differential/run.sh
# semantic rejection is enforced only after F1:
STRICT=1 SING_BOX_REF=/path/to/sing-box bash tests/differential/run.sh
```

Rules:

- valid corpus (`lx/`, `tachyon/`): **both** binaries must exit 0;
- `invalid/`: reference must reject; until semantic validation lands (F1) a
  `tachyon-core` acceptance is reported as `GAP` (failure only under `STRICT=1`).

`SING_BOX_REF` is provided by CI (downloaded from Leadaxe/sing-box-lx releases).
