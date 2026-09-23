use std::io;
use tokio::net::TcpStream;

use crate::inbound::Target;

/// block outbound: reject every connection.
#[derive(Default)]
pub struct Block;

impl Block {
    pub async fn connect(&self, _target: &Target) -> io::Result<TcpStream> {
        Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "blocked by outbound",
        ))
    }
}
