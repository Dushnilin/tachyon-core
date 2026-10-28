# CLI Interface Specification

`tachyon-core` provides a standard command-line interface for OpenWrt and Linux environments.

## Commands

### `version`
Prints the current version of the core.
```bash
tachyon-core version
```

### `check -c <path>`
Validates the JSON configuration file at `<path>`.
```bash
tachyon-core check -c /etc/tachyon/config.json
```
This performs schema validation and semantic checks against the `sing-box` compatibility contract.

### `run -c <path>`
Starts the core with the specified configuration.
```bash
tachyon-core run -c /etc/tachyon/config.json
```

### `generate <type>`
Generates cryptographic material.
- `reality-keypair`: Generates X25519 keypair for REALITY.
- `wg-keypair`: Generates WireGuard/AmneziaWG keypair.
- `tls-keypair <sni> [-m <months>]`: Generates self-signed ECDSA P-256 certificate and key (PEM).
- `uuid` / `rand`: Generates UUID v4 or random key.

### `rule-set <command>`
Manages SRS v5 binary rules.
- `compile`: Compiles JSON rules to `.srs`.
- `match`: Tests rule matching against a target.

## Environment Variables
- `TACHYON_WORKERS`: Number of worker threads.
- `TACHYON_SMOL_TCP_BUF`: TCP socket buffer size for userspace stacks (KiB).
