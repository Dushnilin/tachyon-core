//! Configuration schema and parser for Tailscale endpoints.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde_json::{Map, Value};
use smoltcp::wire::IpCidr;

use crate::inbound::udp::DEFAULT_UDP_TIMEOUT;
use crate::outbound::urltest::parse_duration;

pub const DEFAULT_CONTROL_URL: &str = "https://controlplane.tailscale.com";
pub const DEFAULT_LISTEN_PORT: u16 = 41641;

#[derive(Clone, Debug, PartialEq)]
pub struct TailscaleConfig {
    pub tag: String,
    pub state_directory: Option<PathBuf>,
    pub auth_key: Option<String>,
    pub control_url: String,
    pub ephemeral: bool,
    pub hostname: Option<String>,
    pub accept_routes: bool,
    pub exit_node: Option<String>,
    pub exit_node_allow_lan_access: bool,
    pub advertise_routes: Vec<IpCidr>,
    pub advertise_exit_node: bool,
    pub advertise_tags: Vec<String>,
    pub listen_port: u16,
    pub relay_server_port: Option<u16>,
    pub relay_server_static_endpoints: Vec<SocketAddr>,
    pub system_interface: bool,
    pub system_interface_name: Option<String>,
    pub system_interface_mtu: Option<u32>,
    pub udp_timeout: Duration,
    pub taildrop_directory: Option<PathBuf>,
}

impl TailscaleConfig {
    pub fn parse(obj: &Map<String, Value>, at: &str) -> anyhow::Result<Self> {
        let tag = obj
            .get("tag")
            .and_then(Value::as_str)
            .unwrap_or(at)
            .to_string();

        let state_directory = obj
            .get("state_directory")
            .and_then(Value::as_str)
            .map(PathBuf::from);

        let auth_key = obj
            .get("auth_key")
            .and_then(Value::as_str)
            .map(ToString::to_string);

        let control_url = obj
            .get("control_url")
            .and_then(Value::as_str)
            .unwrap_or(DEFAULT_CONTROL_URL)
            .to_string();

        let ephemeral = obj
            .get("ephemeral")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let hostname = obj
            .get("hostname")
            .and_then(Value::as_str)
            .map(ToString::to_string);

        let accept_routes = obj
            .get("accept_routes")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let exit_node = obj
            .get("exit_node")
            .and_then(Value::as_str)
            .map(ToString::to_string);

        let exit_node_allow_lan_access = obj
            .get("exit_node_allow_lan_access")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let mut advertise_routes = Vec::new();
        if let Some(Value::Array(items)) = obj.get("advertise_routes") {
            for (i, v) in items.iter().enumerate() {
                if let Some(s) = v.as_str() {
                    let cidr = s.parse::<IpCidr>().map_err(|_| {
                        anyhow::anyhow!("{at}.advertise_routes[{i}]: invalid CIDR {s}")
                    })?;
                    advertise_routes.push(cidr);
                }
            }
        } else if let Some(Value::String(s)) = obj.get("advertise_routes") {
            let cidr = s
                .parse::<IpCidr>()
                .map_err(|_| anyhow::anyhow!("{at}.advertise_routes: invalid CIDR {s}"))?;
            advertise_routes.push(cidr);
        }

        let advertise_exit_node = obj
            .get("advertise_exit_node")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let mut advertise_tags = Vec::new();
        if let Some(Value::Array(items)) = obj.get("advertise_tags") {
            for v in items {
                if let Some(s) = v.as_str() {
                    advertise_tags.push(s.to_string());
                }
            }
        } else if let Some(Value::String(s)) = obj.get("advertise_tags") {
            advertise_tags.push(s.to_string());
        }

        let listen_port = match obj.get("listen_port") {
            None => DEFAULT_LISTEN_PORT,
            Some(value) => value
                .as_u64()
                .and_then(|value| u16::try_from(value).ok())
                .ok_or_else(|| anyhow::anyhow!("{at}.listen_port: expected a port in 0..65535"))?,
        };

        let relay_server_port = obj
            .get("relay_server_port")
            .and_then(Value::as_u64)
            .map(|p| p as u16);

        let mut relay_server_static_endpoints = Vec::new();
        if let Some(Value::Array(items)) = obj.get("relay_server_static_endpoints") {
            for (i, v) in items.iter().enumerate() {
                if let Some(s) = v.as_str() {
                    let addr = s.parse::<SocketAddr>().map_err(|_| {
                        anyhow::anyhow!(
                            "{at}.relay_server_static_endpoints[{i}]: invalid socket address {s}"
                        )
                    })?;
                    relay_server_static_endpoints.push(addr);
                }
            }
        }

        let system_interface = obj
            .get("system_interface")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let system_interface_name = obj
            .get("system_interface_name")
            .and_then(Value::as_str)
            .map(ToString::to_string);

        let system_interface_mtu = obj
            .get("system_interface_mtu")
            .and_then(Value::as_u64)
            .map(|m| m as u32);

        let udp_timeout = parse_duration(obj.get("udp_timeout"), DEFAULT_UDP_TIMEOUT, at)?;

        let taildrop_directory = obj
            .get("taildrop_directory")
            .and_then(Value::as_str)
            .map(PathBuf::from);

        Ok(Self {
            tag,
            state_directory,
            auth_key,
            control_url,
            ephemeral,
            hostname,
            accept_routes,
            exit_node,
            exit_node_allow_lan_access,
            advertise_routes,
            advertise_exit_node,
            advertise_tags,
            listen_port,
            relay_server_port,
            relay_server_static_endpoints,
            system_interface,
            system_interface_name,
            system_interface_mtu,
            udp_timeout,
            taildrop_directory,
        })
    }
}
