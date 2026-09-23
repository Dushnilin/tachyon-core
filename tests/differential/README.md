# Differential tests

`run.sh` compares `tachyon-core check` against the reference `sing-box-lx check`
on the golden corpus:

```bash
cargo build --workspace
SING_BOX_REF=/path/to/sing-box bash tests/differential/run.sh
# semantic rejection is enforced by default in CI/docker (STRICT=1);
# locally you can run lenient with STRICT=0:
STRICT=0 SING_BOX_REF=/path/to/sing-box bash tests/differential/run.sh
```

Rules:

- valid corpus (`lx/`, `tachyon/`): **both** binaries must exit 0;
- `invalid/`: reference must reject and `tachyon-core` must reject too
  (semantic validation, F1). With `STRICT=0` a `tachyon-core` acceptance is
  downgraded to a `GAP` report instead of a failure.

`SING_BOX_REF` is provided by CI (downloaded from Leadaxe/sing-box-lx releases).
