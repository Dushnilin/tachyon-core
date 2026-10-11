//! Persistent private identity. Never rewrite a Go/LX state store or silently
//! replace an unreadable identity with a new node.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use x25519_dalek::StaticSecret;

use super::control::{from_hex, to_hex};

const IDENTITY_FILE: &str = "tachyon-native-identity.json";
const MAX_STATE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
struct Identity {
    machine_key: String,
    node_key: String,
    // Preserve this field on import even when tailnet lock is disabled. A
    // private signing key alone is not authority to accept unsigned peers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    network_lock_key: Option<String>,
}

pub struct Keys {
    pub machine: StaticSecret,
    pub node: StaticSecret,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn private_key(text: &str) -> io::Result<[u8; 32]> {
    let hex = text
        .strip_prefix("privkey:")
        .ok_or_else(|| invalid("tailscale: expected a private identity key"))?;
    let mut bytes = [0; 32];
    from_hex(hex, &mut bytes).map_err(|_| invalid("tailscale: invalid private identity key"))?;
    if bytes == [0; 32] {
        return Err(invalid("tailscale: zero private identity key"));
    }
    Ok(bytes)
}

fn read_json(path: &Path) -> io::Result<Value> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_STATE_BYTES {
        return Err(invalid("tailscale: state file exceeds size limit"));
    }
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|_| invalid("tailscale: invalid state JSON"))
}

fn decode_store(value: &Value, field: &str) -> io::Result<Vec<u8>> {
    let encoded = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("tailscale: missing state store field"))?;
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| invalid("tailscale: invalid state store encoding"))
}

fn import_go(path: &Path) -> io::Result<Identity> {
    let store = read_json(path)?;
    let profile = decode_store(&store, "_current-profile")?;
    let profile =
        std::str::from_utf8(&profile).map_err(|_| invalid("tailscale: invalid current profile"))?;
    let bytes = decode_store(&store, profile)?;
    let profile: Value =
        serde_json::from_slice(&bytes).map_err(|_| invalid("tailscale: invalid profile JSON"))?;
    let persist = profile
        .get("Config")
        .or_else(|| profile.get("Persist"))
        .ok_or_else(|| invalid("tailscale: missing persisted profile"))?;
    let machine = decode_store(&store, "_machinekey")?;
    let machine_key = String::from_utf8(machine)
        .map_err(|_| invalid("tailscale: invalid machine key encoding"))?;
    let node_key = persist
        .get("PrivateNodeKey")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("tailscale: missing private node key"))?
        .to_owned();
    let network_lock_key = persist
        .get("NetworkLockKey")
        .and_then(Value::as_str)
        .filter(|key| !key.is_empty())
        .map(str::to_owned);
    Ok(Identity {
        machine_key,
        node_key,
        network_lock_key,
    })
}

fn fresh_identity() -> io::Result<Identity> {
    let mut bytes = [0; 64];
    getrandom::fill(&mut bytes)
        .map_err(|_| io::Error::other("tailscale: identity entropy unavailable"))?;
    Ok(Identity {
        machine_key: format!("privkey:{}", to_hex(&bytes[..32])),
        node_key: format!("privkey:{}", to_hex(&bytes[32..])),
        network_lock_key: None,
    })
}

fn keys(identity: &Identity) -> io::Result<Keys> {
    Ok(Keys {
        machine: StaticSecret::from(private_key(&identity.machine_key)?),
        node: StaticSecret::from(private_key(&identity.node_key)?),
    })
}

fn persist(dir: &Path, identity: &Identity) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    let mut suffix = [0; 8];
    getrandom::fill(&mut suffix)
        .map_err(|_| io::Error::other("tailscale: state entropy unavailable"))?;
    let temporary = dir.join(format!(".identity-{}", to_hex(&suffix)));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&temporary)?;
        let json = serde_json::to_vec(identity).map_err(io::Error::other)?;
        file.write_all(&json)?;
        file.sync_all()?;
        // Publish once. A concurrent first start must not overwrite another
        // freshly created private identity (rename replaces files on Unix).
        fs::hard_link(&temporary, dir.join(IDENTITY_FILE))?;
        fs::remove_file(&temporary)?;
        #[cfg(unix)]
        fs::File::open(dir)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

pub fn load(dir: Option<&Path>, ephemeral: bool) -> io::Result<Keys> {
    if ephemeral {
        return keys(&fresh_identity()?);
    }
    let dir = dir.ok_or_else(|| invalid("tailscale: persistent nodes require state_directory"))?;
    let identity_path = dir.join(IDENTITY_FILE);
    match read_json(&identity_path) {
        Ok(value) => {
            let identity: Identity = serde_json::from_value(value)
                .map_err(|_| invalid("tailscale: invalid native identity"))?;
            return keys(&identity);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let go_path = dir.join("tailscaled.state");
    let identity = match fs::metadata(&go_path) {
        Ok(_) => import_go(&go_path)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // The scaffold wrote public keys to tailscale.state. These cannot
            // be recovered as private keys; require explicit operator repair.
            if dir.join("tailscale.state").try_exists()? || dir.join("state.json").try_exists()? {
                return Err(invalid(
                    "tailscale: legacy scaffold identity is not recoverable",
                ));
            }
            fresh_identity()?
        }
        Err(error) => return Err(error),
    };
    let keys = keys(&identity)?;
    match persist(dir, &identity) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let value = read_json(&identity_path)?;
            let identity: Identity = serde_json::from_value(value)
                .map_err(|_| invalid("tailscale: invalid concurrent native identity"))?;
            return self::keys(&identity);
        }
        Err(error) => return Err(error),
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directory() -> std::path::PathBuf {
        let mut bytes = [0; 8];
        getrandom::fill(&mut bytes).unwrap();
        let dir = std::env::temp_dir().join(format!("tachyon-identity-{}", to_hex(&bytes)));
        fs::create_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn private_identity_survives_restart() {
        let dir = directory();
        let first = load(Some(&dir), false).unwrap();
        let second = load(Some(&dir), false).unwrap();
        assert_eq!(first.machine.to_bytes(), second.machine.to_bytes());
        assert_eq!(first.node.to_bytes(), second.node.to_bytes());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(dir.join(IDENTITY_FILE))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn import_go_preserves_private_keys_and_original_store() {
        let dir = directory();
        let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
        let machine = format!("privkey:{}", to_hex(&[7; 32]));
        let node = format!("privkey:{}", to_hex(&[9; 32]));
        let profile =
            serde_json::to_vec(&serde_json::json!({"Config": {"PrivateNodeKey": node}})).unwrap();
        let store = serde_json::to_vec(&serde_json::json!({
            "_machinekey": encode(machine.as_bytes()), "_current-profile": encode(b"profile-test"),
            "profile-test": encode(&profile)
        }))
        .unwrap();
        fs::write(dir.join("tailscaled.state"), &store).unwrap();
        let imported = load(Some(&dir), false).unwrap();
        assert_eq!(imported.machine.to_bytes(), [7; 32]);
        assert_eq!(imported.node.to_bytes(), [9; 32]);
        assert_eq!(fs::read(dir.join("tailscaled.state")).unwrap(), store);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn damaged_or_public_identity_never_generates_a_replacement() {
        let dir = directory();
        for value in [
            b"broken JSON".as_slice(),
            br#"{"machine_key":"mkey:bad","node_key":"nodekey:bad"}"#,
        ] {
            fs::write(dir.join(IDENTITY_FILE), value).unwrap();
            assert!(load(Some(&dir), false).is_err());
            assert_eq!(fs::read(dir.join(IDENTITY_FILE)).unwrap(), value);
        }
        fs::remove_dir_all(dir).unwrap();
    }
}
