# Differential tests

Harness comparing `tachyon-core` against the reference `sing-box` /
`sing-box-lx` binary on the golden corpus. Fails when:

- `check` exit codes differ;
- formatted output of `check` errors diverge (message contract);
- routing decision for the probe set (fixed domain/IP/port queries) differs.

The reference binary is provided via `SING_BOX_REF` env var (path), or downloaded
in CI from Leadaxe/sing-box-lx releases.
