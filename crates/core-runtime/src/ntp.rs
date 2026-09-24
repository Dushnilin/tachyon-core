//! NTP section runtime: optional periodic SNTP query (reference
//! `ntp.NewService` + `option.NTPOptions`). `write_to_system` sets CLOCK_REALTIME
//! and is gated the same way the reference gates it behind a security feature
//! check — we only attempt the clock_settime and log failures.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::net::UdpSocket;

use crate::logging;
use crate::outbound::urltest::parse_duration;

/// Default poll interval when `ntp.interval` is unset (sing-box docs: 30m).
const DEFAULT_INTERVAL: Duration = Duration::from_secs(30 * 60);
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);

pub struct NtpService {
    server: SocketAddr,
    interval: Duration,
    write_to_system: bool,
}

impl NtpService {
    /// Build from the root document; `Ok(None)` when the section is absent
    /// or `enabled` is false (reference: `ntpOptions.Enabled` gate).
    pub fn build(root: &Value) -> anyhow::Result<Option<Arc<Self>>> {
        let Some(ntp) = root.get("ntp") else {
            return Ok(None);
        };
        let map = ntp
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("ntp: must be a JSON object"))?;
        if !map.get("enabled").and_then(Value::as_bool).unwrap_or(false) {
            return Ok(None);
        }
        let server = server_endpoint(map)?;
        let interval = parse_duration(map.get("interval"), DEFAULT_INTERVAL, "ntp.interval")?;
        let interval = if interval.is_zero() {
            DEFAULT_INTERVAL
        } else {
            interval
        };
        let write_to_system = map
            .get("write_to_system")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        logging::info(format_args!(
            "ntp service: server {server}, interval {interval:?}, write_to_system {write_to_system}"
        ));
        Ok(Some(Arc::new(Self {
            server,
            interval,
            write_to_system,
        })))
    }

    pub fn spawn(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            // Immediate first sync, then poll (reference Start → query loop).
            this.sync_once().await;
            loop {
                tokio::time::sleep(this.interval).await;
                this.sync_once().await;
            }
        })
    }

    async fn sync_once(&self) {
        match self.query().await {
            Ok(offset_ms) => {
                logging::info(format_args!(
                    "ntp: synchronized with {} (offset {offset_ms:+.1} ms)",
                    self.server
                ));
                if self.write_to_system {
                    self.write_clock(offset_ms).await;
                }
            }
            Err(err) => {
                logging::debug(format_args!("ntp: query {}: {err}", self.server));
            }
        }
    }

    /// Minimal SNTP client (RFC 5905 client mode, 48-byte packet).
    async fn query(&self) -> anyhow::Result<f64> {
        let bind = if self.server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let sock = UdpSocket::bind(bind).await?;
        let mut req = [0u8; 48];
        req[0] = 0x23; // LI=0, VN=4, Mode=3 (client)
        sock.send_to(&req, self.server).await?;
        let mut buf = [0u8; 48];
        let (n, _from) = tokio::time::timeout(QUERY_TIMEOUT, sock.recv_from(&mut buf))
            .await
            .map_err(|_| anyhow::anyhow!("timeout"))?
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        if n < 48 {
            anyhow::bail!("short response {n} bytes");
        }
        let mode = buf[0] & 0x07;
        if mode != 4 && mode != 5 {
            anyhow::bail!("unexpected mode {mode}");
        }
        let stratum = buf[1];
        if stratum == 0 {
            anyhow::bail!("kiss-o'-death");
        }
        // Transmit timestamp: bytes 40..48, seconds since 1900-01-01.
        let tx_secs = u32::from_be_bytes([buf[40], buf[41], buf[42], buf[43]]) as f64;
        let tx_frac =
            u32::from_be_bytes([buf[44], buf[45], buf[46], buf[47]]) as f64 / 2f64.powi(32);
        let server_unix = tx_secs - 2_208_988_800.0 + tx_frac;
        let local_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| anyhow::anyhow!("clock before epoch"))?
            .as_secs_f64();
        Ok((server_unix - local_unix) * 1000.0)
    }

    async fn write_clock(&self, offset_ms: f64) {
        #[cfg(unix)]
        {
            let offset = Duration::from_secs_f64((offset_ms / 1000.0).abs());
            let now = std::time::SystemTime::now();
            let result = if offset_ms >= 0.0 {
                Some(now + offset)
            } else {
                now.checked_sub(offset)
            };
            let Some(target) = result else {
                logging::warn(format_args!("ntp: offset {offset_ms:+.1} ms before epoch"));
                return;
            };
            let since = match target.duration_since(std::time::UNIX_EPOCH) {
                Ok(d) => d,
                Err(err) => {
                    logging::warn(format_args!("ntp: write_to_system: {err}"));
                    return;
                }
            };
            let ts = libc::timespec {
                #[allow(deprecated)]
                tv_sec: since.as_secs() as libc::time_t,
                tv_nsec: since.subsec_nanos() as libc::c_long,
            };
            let rc = unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &ts) };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                logging::warn(format_args!(
                    "ntp: write_to_system: clock_settime: {err} (needs CAP_SYS_TIME)"
                ));
            }
        }
        #[cfg(not(unix))]
        {
            let _ = offset_ms;
            logging::warn(format_args!(
                "ntp: write_to_system is not supported on this platform"
            ));
        }
    }
}

fn server_endpoint(map: &serde_json::Map<String, Value>) -> anyhow::Result<SocketAddr> {
    let host = map
        .get("server")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("ntp: missing server"))?;
    let port = map
        .get("server_port")
        .and_then(Value::as_u64)
        .and_then(|p| u16::try_from(p).ok())
        .unwrap_or(123);
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        Ok(SocketAddr::new(ip, port))
    } else {
        // Defer DNS to connect time: resolve via the dns service like other
        // outbounds; NTP servers are almost always literals in practice.
        let addrs = std::net::ToSocketAddrs::to_socket_addrs(&(host, port))
            .map_err(|e| anyhow::anyhow!("ntp: resolve {host}: {e}"))?
            .collect::<Vec<_>>();
        addrs
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("ntp: no address for {host}"))
    }
}
