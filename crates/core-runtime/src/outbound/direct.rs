use std::io;
use tokio::net::TcpStream;

use crate::inbound::Target;

/// direct outbound: dial the target from the local host.
#[derive(Default)]
pub struct Direct;

impl Direct {
    pub async fn connect(&self, target: &Target) -> io::Result<TcpStream> {
        match target {
            Target::Ip(addr) => TcpStream::connect(*addr).await,
            Target::Domain(host, port) => TcpStream::connect((host.as_str(), *port)).await,
        }
    }
}
