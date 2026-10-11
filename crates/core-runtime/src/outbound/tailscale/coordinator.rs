//! Reconnecting control map stream. No private keys, auth keys or login URLs
//! are written to logs. Endpoint cancellation aborts the stream reader too.

use std::io;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::sync::{mpsc, watch};
use x25519_dalek::{PublicKey, StaticSecret};

use super::config::TailscaleConfig;
use super::control::node_key_str;
use super::control_wire::{CAPABILITY_VERSION, ControlConnection, read_maps};
use super::netmap::Netmap;
use crate::logging;

pub fn spawn(
    cfg: TailscaleConfig,
    machine: StaticSecret,
    node: StaticSecret,
    disco_public: [u8; 32],
    map: Arc<RwLock<Netmap>>,
    updates: watch::Sender<u64>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut revision = 0u64;
        loop {
            if let Err(error) = session(
                &cfg,
                &machine,
                &node,
                &disco_public,
                &map,
                &updates,
                &mut revision,
            )
            .await
            {
                if matches!(
                    error.kind(),
                    io::ErrorKind::PermissionDenied | io::ErrorKind::InvalidData
                ) {
                    if let Ok(mut map) = map.write() {
                        *map = Netmap::default();
                    }
                    revision = revision.wrapping_add(1);
                    let _ = updates.send(revision);
                }
                logging::warn(format_args!(
                    "tailscale[{}]: control unavailable: {}",
                    cfg.tag, error
                ));
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    })
}

async fn session(
    cfg: &TailscaleConfig,
    machine: &StaticSecret,
    node: &StaticSecret,
    disco_public: &[u8; 32],
    map: &Arc<RwLock<Netmap>>,
    updates: &watch::Sender<u64>,
    revision: &mut u64,
) -> io::Result<()> {
    let control = ControlConnection::connect(&cfg.control_url, machine).await?;
    let node_key = node_key_str(&PublicKey::from(node));
    let disco_key = format!("discokey:{}", super::control::to_hex(disco_public));
    let mut hostinfo = json!({
        "OS":"linux", "Hostname": cfg.hostname.as_deref().unwrap_or("tachyon-core"),
        "RoutableIPs":cfg.advertise_routes.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "RequestTags":cfg.advertise_tags,
    });
    let mut register = json!({"Version":CAPABILITY_VERSION,"NodeKey":node_key,"Hostinfo":hostinfo,"Ephemeral":cfg.ephemeral});
    if let Some(auth) = &cfg.auth_key {
        register["Auth"] = json!({"AuthKey":auth});
    }
    let result = tokio::time::timeout(
        Duration::from_secs(20),
        control.json("/machine/register", &register),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tailscale: register timeout"))??;
    if result
        .get("Error")
        .and_then(Value::as_str)
        .is_some_and(|error| !error.is_empty())
        || result
            .get("AuthURL")
            .and_then(Value::as_str)
            .is_some_and(|url| !url.is_empty())
        || result.get("MachineAuthorized").and_then(Value::as_bool) == Some(false)
        || result.get("NodeKeyExpired").and_then(Value::as_bool) == Some(true)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "tailscale: node authorization is required",
        ));
    }
    let request = json!({"Version":CAPABILITY_VERSION,"NodeKey":node_key,"DiscoKey":disco_key,"Compress":"","KeepAlive":true,"Stream":true,"Hostinfo":hostinfo,"Endpoints":[]});
    let stream = control.request("/machine/map", &request).await?;
    let (send, mut maps) = mpsc::channel(8);
    let reader = tokio::spawn(read_maps(stream, send));
    struct Guard(tokio::task::JoinHandle<io::Result<()>>);
    impl Drop for Guard {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let mut reader = Guard(reader);
    let mut home = 0u16;
    loop {
        let value = tokio::select! {
            result=&mut reader.0=>return match result {Ok(result)=>result,Err(_)=>Err(io::Error::other("tailscale: map reader stopped"))},
            value=maps.recv()=>value.ok_or_else(||io::Error::other("tailscale: map reader stopped"))?,
        };
        let assigned = {
            let mut current = map
                .write()
                .map_err(|_| io::Error::other("tailscale: map lock poisoned"))?;
            current.update(&value)?;
            if !current.own_addresses.is_empty() {
                home = current.choose_home_derp();
                current.home_derp = home;
            }
            !current.own_addresses.is_empty()
        };
        *revision = revision.wrapping_add(1);
        let _ = updates.send(*revision);
        if assigned && *revision == 1 {
            logging::info(format_args!(
                "tailscale[{}]: authenticated network map received",
                cfg.tag
            ));
        }
        if home != 0
            && hostinfo
                .get("NetInfo")
                .and_then(|info| info.get("PreferredDERP"))
                .and_then(Value::as_u64)
                != Some(u64::from(home))
        {
            hostinfo["NetInfo"] = json!({"PreferredDERP":home,"UDP":true});
            let request = json!({"Version":CAPABILITY_VERSION,"NodeKey":node_key,"DiscoKey":disco_key,"Stream":false,"OmitPeers":true,"Hostinfo":hostinfo,"Endpoints":[]});
            // Updating the home relay must use the SAME connection while the
            // first map is streaming; opening a second map stream evicts it.
            tokio::time::timeout(Duration::from_secs(20), async {
                let mut response = control.request("/machine/map", &request).await?;
                while let Some(bytes) = response.data().await {
                    let bytes = bytes.map_err(io::Error::other)?;
                    response
                        .flow_control()
                        .release_capacity(bytes.len())
                        .map_err(io::Error::other)?;
                }
                Ok::<_, io::Error>(())
            })
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "tailscale: home relay update timeout",
                )
            })??;
        }
    }
}
