//! RFC 6455 server side for the Clash API's streaming endpoints.
//!
//! The reference upgrades `/logs`, `/traffic` and `/connections` with the
//! `sagernet/ws` upgrader and then only ever writes text frames — it never
//! reads from the socket, so a client's pings stay unread in the kernel
//! buffer and a broken pipe ends the loop. This module is the same shape:
//! the handshake, the same rejections, and an unmasked text frame.

use std::io;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use sha1::{Digest, Sha1};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// RFC 6455 §1.3 magic string the accept value is derived from.
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// `Sec-WebSocket-Key` is base64 of exactly this many bytes.
const NONCE_LEN: usize = 24;

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// The request wants a websocket at all (the clash handlers test only the
/// `Upgrade` header, then hand the request to the upgrader).
pub fn wants_upgrade(headers: &[(String, String)]) -> bool {
    header(headers, "upgrade").is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
}

/// A handshake the upgrader refused: the status, the extra header the
/// reference adds, and the reason line it answers with.
#[derive(Debug, PartialEq, Eq)]
pub struct Rejection {
    pub status: u16,
    extra: &'static str,
    reason: &'static str,
}

const fn http_text(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        405 => "Method Not Allowed",
        426 => "Upgrade Required",
        505 => "HTTP Version Not Supported",
        _ => "",
    }
}

impl Rejection {
    /// The whole response, as `sagernet/ws` writes it after hijacking:
    /// a plain-text head with the length of the reason, nothing else.
    pub fn response(&self) -> String {
        let reason = self.reason;
        format!(
            "HTTP/1.1 {} {}\r\nContent-Type: text/plain; charset=utf-8\r\n{}Content-Length: {}\r\n\r\n{reason}",
            self.status,
            http_text(self.status),
            self.extra,
            reason.len(),
        )
    }
}

/// Validate the handshake in the reference upgrader's order (`server.go`),
/// returning the client's key or the rejection it would send. HTTP version
/// and method are left to the request router, which answers them first.
pub fn validate(headers: &[(String, String)]) -> Result<String, Rejection> {
    if header(headers, "host").is_none_or(|host| host.is_empty()) {
        return Err(reject(400, "", "handshake error: bad \"Host\" header"));
    }
    if !wants_upgrade(headers) {
        return Err(reject(
            400,
            "",
            "handshake error: bad \"Upgrade\" header",
        ));
    }
    let connection = header(headers, "connection").unwrap_or("");
    if connection != "Upgrade"
        && !connection
            .split(',')
            .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
    {
        return Err(reject(
            400,
            "",
            "handshake error: bad \"Connection\" header",
        ));
    }
    let key = header(headers, "sec-websocket-key").unwrap_or("");
    if key.len() != NONCE_LEN {
        return Err(reject(
            400,
            "",
            "handshake error: bad \"Sec-WebSocket-Key\" header",
        ));
    }
    match header(headers, "sec-websocket-version") {
        Some("13") => Ok(key.to_string()),
        Some("") | None => Err(reject(
            400,
            "",
            "handshake error: bad \"Sec-WebSocket-Version\" header",
        )),
        // RFC 6455: an understood version must be offered back with a 426
        Some(_) => Err(reject(
            426,
            "Sec-WebSocket-Version: 13\r\n",
            "handshake error: bad \"Sec-WebSocket-Version\" header",
        )),
    }
}

const fn reject(status: u16, extra: &'static str, reason: &'static str) -> Rejection {
    Rejection {
        status,
        extra,
        reason,
    }
}

/// `Sec-WebSocket-Accept` for a client key (RFC 6455 §4.2.2).
fn accept_value(client_key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(client_key.as_bytes());
    hasher.update(GUID.as_bytes());
    B64.encode(hasher.finalize())
}

/// The whole 101 response: only the upgrade headers, exactly as
/// `httpWriteResponseUpgrade` writes them — the CORS middleware's headers
/// are lost in Go when the connection is hijacked.
fn handshake_head(client_key: &str) -> String {
    format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\r\n",
        accept_value(client_key)
    )
}

/// One server-to-client text frame (FIN set, unmasked, no extension).
fn text_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 10);
    frame.push(0x81);
    match payload.len() {
        len if len < 126 => frame.push(len as u8),
        len if len <= u16::MAX as usize => {
            frame.push(126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        }
        len => {
            frame.push(127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
    }
    frame.extend_from_slice(payload);
    frame
}

/// Send the handshake for `client_key` and switch this stream to the socket.
pub async fn accept(stream: &mut TcpStream, client_key: &str) -> io::Result<()> {
    stream.write_all(handshake_head(client_key).as_bytes()).await
}

/// Write one text frame carrying `payload`.
pub async fn write_text(stream: &mut TcpStream, payload: &[u8]) -> io::Result<()> {
    stream.write_all(&text_frame(payload)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// A browser's own handshake headers; `extra` replaces a header of the
    /// same name (an empty value stands in for the header being absent).
    fn browser(extra: &[(&str, &str)]) -> Vec<(String, String)> {
        let mut all = vec![
            ("Host", "127.0.0.1:9090"),
            ("Upgrade", "websocket"),
            ("Connection", "Upgrade"),
            ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
            ("Sec-WebSocket-Version", "13"),
        ];
        all.extend_from_slice(extra);
        let mut out: Vec<(String, String)> = Vec::new();
        for (name, value) in all {
            match out
                .iter_mut()
                .find(|(known, _)| known.eq_ignore_ascii_case(name))
            {
                Some(slot) => slot.1 = value.to_string(),
                None => out.push((name.to_string(), value.to_string())),
            }
        }
        out
    }

    #[test]
    fn rfc6455_sample_key() {
        // the worked example from RFC 6455 §1.3
        assert_eq!(
            accept_value("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
        assert!(handshake_head("dGhlIHNhbXBsZSBub25jZQ==").contains(
            "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
        ));
    }

    #[test]
    fn a_browser_handshake_is_accepted() {
        assert_eq!(
            validate(&browser(&[])).expect("accepted"),
            "dGhlIHNhbXBsZSBub25jZQ=="
        );
        // `Connection` may list several tokens, case included
        assert!(validate(&browser(&[("Connection", "keep-alive, Upgrade")])).is_ok());
        assert!(validate(&browser(&[("connection", "upgrade")])).is_ok());
    }

    #[test]
    fn a_broken_handshake_gets_the_reference_status() {
        let key = validate(&headers(&[
            ("Host", "x"),
            ("Upgrade", "websocket"),
            ("Connection", "Upgrade"),
            ("Sec-WebSocket-Version", "13"),
        ]))
        .expect_err("missing key");
        assert_eq!(key.status, 400);
        assert_eq!(
            key.response(),
            "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\n\
             Content-Length: 47\r\n\r\nhandshake error: bad \"Sec-WebSocket-Key\" header"
        );

        let short = validate(&browser(&[("Sec-WebSocket-Key", "short")]))
            .expect_err("short key");
        assert_eq!(short.status, 400);

        let version = validate(&browser(&[("Sec-WebSocket-Version", "8")]))
            .expect_err("unsupported version");
        assert_eq!(version.status, 426);
        assert!(version.response().contains("Sec-WebSocket-Version: 13\r\n"));

        let connection = validate(&browser(&[("Connection", "close")]))
            .expect_err("connection token");
        assert_eq!(connection.status, 400);

        let host = validate(&headers(&[
            ("Upgrade", "websocket"),
            ("Connection", "Upgrade"),
            ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
            ("Sec-WebSocket-Version", "13"),
        ]))
        .expect_err("no host");
        assert_eq!(host.status, 400);
    }

    #[test]
    fn a_short_text_frame_is_two_header_bytes() {
        assert_eq!(text_frame(b"Hi"), vec![0x81, 0x02, b'H', b'i']);
    }

    #[test]
    fn the_extended_lengths_are_network_order() {
        let medium = text_frame(&vec![b'x'; 300]);
        assert_eq!(&medium[..4], &[0x81, 126, 0x01, 0x2c]);

        let long = text_frame(&vec![b'x'; 70_000]);
        assert_eq!(&long[..2], &[0x81, 127]);
        assert_eq!(
            u64::from_be_bytes(long[2..10].try_into().expect("len")),
            70_000
        );
        assert_eq!(long.len(), 70_010);
    }

    #[test]
    fn the_upgrade_is_recognised_by_the_header_alone() {
        assert!(wants_upgrade(&headers(&[("Upgrade", "websocket")])));
        assert!(wants_upgrade(&headers(&[("upgrade", "WebSocket")])));
        assert!(!wants_upgrade(&headers(&[("upgrade", "h2c")])));
        assert!(!wants_upgrade(&[]));
    }
}
