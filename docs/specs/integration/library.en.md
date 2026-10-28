# Library Embedding Specification (Rust)

`tachyon-core` can be embedded directly into Rust applications via the `core-runtime` and `core-config` crates.

## Core Types & Functions

### `core_config::check_str(raw: &str) -> Result<(), String>`
Validates a raw JSON configuration string before starting the runtime.

### `core_runtime::start(root: &serde_json::Value) -> anyhow::Result<BoxInstance>`
Starts the data plane (inbounds, outbounds, router, DNS, Clash API) asynchronously and returns a `BoxInstance` handle.

### `BoxInstance`
Manages the lifecycle of the running proxy instance.
- `inbound_addrs(&self) -> &[(String, SocketAddr)]`: Returns bound addresses of all inbounds.
- `clash_api_addr(&self) -> Option<SocketAddr>`: Returns bound address of the Clash API controller.
- `reload_in_place(&mut self, new_root: &Value) -> anyhow::Result<()>`: Hot-reloads routing rules, outbounds, and DNS without dropping active inbound listeners.
- `shutdown(&self)`: Aborts all listeners and tasks.
- `shutdown_wait(&mut self)`: Aborts all tasks and waits for sockets to be fully released.

## Example Usage

```rust
use serde_json::Value;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config_str = r#"{
        "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": 1080}],
        "outbounds": [{"type": "direct"}]
    }"#;

    // 1. Validate config
    core_config::check_str(config_str).map_err(|e| anyhow::anyhow!(e))?;

    // 2. Start instance
    let root: Value = serde_json::from_str(config_str)?;
    let mut instance = core_runtime::start(&root).await?;

    println!("Listening on: {:?}", instance.inbound_addrs());

    // 3. Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    instance.shutdown_wait().await;
    Ok(())
}
```
