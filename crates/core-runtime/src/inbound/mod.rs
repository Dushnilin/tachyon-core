use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::outbound::shadowsocks::stream::{SsReader, SsWriter};
use crate::route::Router;

pub mod mixed;

/// Object-safe stream for dial results (TCP, TLS, future transports).
pub trait ProxyStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ProxyStream for T {}
pub type AnyStream = Box<dyn ProxyStream>;
pub type AnyRead = Box<dyn AsyncRead + Send + Unpin>;
pub type AnyWrite = Box<dyn AsyncWrite + Send + Unpin>;

/// An established upstream connection: raw streams or a shadowsocks codec.
pub enum Conn {
    Plain(AnyStream),
    Shadowsocks(Box<SsReader<AnyRead>>, SsWriter<AnyWrite>),
}

/// Relay the client stream into an established upstream connection.
pub async fn pump_conn(client: TcpStream, conn: Conn) -> io::Result<()> {
    match conn {
        Conn::Plain(mut upstream) => {
            let mut client_stream: AnyStream = Box::new(client);
            tokio::io::copy_bidirectional(&mut client_stream, &mut upstream).await?;
            Ok(())
        }
        Conn::Shadowsocks(mut reader, mut writer) => {
            let (mut client_read, mut client_write) = client.into_split();
            let mut up_buf = vec![0u8; 0x3FFF];
            let mut down_buf = vec![0u8; 0x3FFF];
            let up = async {
                loop {
                    let n = client_read.read(&mut up_buf).await?;
                    if n == 0 {
                        return Ok(());
                    }
                    writer.write_chunk(&up_buf[..n]).await?;
                }
            };
            let down = async {
                loop {
                    match reader.read(&mut down_buf).await {
                        Ok(0) => return Ok(()),
                        Ok(n) => client_write.write_all(&down_buf[..n]).await?,
                        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                            return Ok(());
                        }
                        Err(err) => return Err(err),
                    }
                }
            };
            tokio::try_join!(up, down).map(|_| ())
        }
    }
}

#[derive(Clone, Debug)]
pub enum Target {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl Target {
    pub fn port(&self) -> u16 {
        match self {
            Target::Ip(addr) => addr.port(),
            Target::Domain(_, port) => *port,
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Ip(addr) => write!(f, "{addr}"),
            Target::Domain(host, port) => write!(f, "{host}:{port}"),
        }
    }
}

pub fn require_u16(
    obj: &serde_json::Map<String, Value>,
    key: &str,
    at: &str,
) -> anyhow::Result<u16> {
    obj.get(key)
        .and_then(Value::as_u64)
        .and_then(|v| u16::try_from(v).ok())
        .ok_or_else(|| anyhow::anyhow!("{at}: missing or invalid {key}"))
}

/// Copy both directions until one side closes.
pub async fn pump<A, B>(mut a: A, mut b: B) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional(&mut a, &mut b).await
}

/// Dial the proxy target through the router's default outbound.
pub async fn dial(router: &Arc<Router>, target: &Target) -> io::Result<Conn> {
    router.connect(target).await
}
