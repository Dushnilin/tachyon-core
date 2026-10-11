//! Stream protocol sniffing (TLS / HTTP / DNS / BitTorrent / SSH / RDP)
//! with sing-box `PeekStream` semantics: accumulate payload under a deadline,
//! re-run sniffers on the full prefix, replay the prefix upstream afterwards.
//! Packet sniffing (DNS / QUIC / STUN / BitTorrent / DTLS / NTP) is
//! `PeekPacket`: the datagrams are only looked at, never consumed.

use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt};

use super::rule::DEFAULT_SNIFF_TIMEOUT;
use super::{ConnContext, SniffError};
use crate::logging;
/// Server-first ports: sniffing would race the server greeting.
const SKIP_PORTS: [u16; 7] = [25, 465, 587, 143, 993, 110, 995];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Matched,
    NeedMore,
    NoMatch,
}

type SnifferFn = fn(&[u8], &mut ConnContext) -> Outcome;

fn sniffer_by_name(name: &str) -> Option<SnifferFn> {
    match name {
        "tls" => Some(sniff_tls),
        "http" => Some(sniff_http),
        "dns" => Some(sniff_dns_stream),
        "bittorrent" => Some(sniff_bittorrent),
        "ssh" => Some(sniff_ssh),
        "rdp" => Some(sniff_rdp),
        _ => None,
    }
}

fn default_stream_sniffers() -> Vec<SnifferFn> {
    vec![
        sniff_tls,
        sniff_http,
        sniff_dns_stream,
        sniff_bittorrent,
        sniff_ssh,
        sniff_rdp,
    ]
}

type PacketSnifferFn = fn(&[u8], &mut ConnContext) -> bool;

/// The reference default set for a packet connection, in its order
/// (`route/route.go` actionSniff). QUIC is not in the table: it alone needs
/// every datagram of the flow, not just the first.
const PACKET_SNIFFERS: [(&str, PacketSnifferFn); 6] = [
    ("dns", sniff_dns_packet),
    ("stun", sniff_stun),
    ("bittorrent", sniff_utp),
    ("bittorrent", sniff_udp_tracker),
    ("dtls", sniff_dtls),
    ("ntp", sniff_ntp),
];

/// Reference `actionSniff` for a packet connection: `datagrams` is every
/// datagram the flow has sent so far, first one first. A QUIC ClientHello
/// split across datagrams leaves `SniffError::NeedMore` and the timeout on the
/// context, so the caller can hold the flow and come back with the next one.
pub(crate) fn action_sniff_packet(
    datagrams: &[&[u8]],
    ctx: &mut ConnContext,
    configured: &[String],
    timeout: Duration,
) {
    if ctx.protocol.is_some() {
        logging::debug(format_args!("duplicate sniff skipped"));
        return;
    }
    let Some(first) = datagrams.first() else {
        return;
    };
    let enabled = |name: &str| configured.is_empty() || configured.iter().any(|n| n == name);
    ctx.sniffer_names = configured.to_vec();
    ctx.sniff_error = None;
    let (dns, rest) = PACKET_SNIFFERS.split_at(1);
    let matched = dns
        .iter()
        .any(|(name, sniffer)| enabled(name) && sniffer(first, ctx))
        || (enabled("quic") && sniff_quic_packets(datagrams, ctx, timeout))
        || rest
            .iter()
            .any(|(name, sniffer)| enabled(name) && sniffer(first, ctx));
    if matched {
        logging::debug(format_args!(
            "sniffed packet protocol: {:?}, domain: {:?}",
            ctx.protocol, ctx.domain
        ));
    }
}

fn sniff_quic_packets(datagrams: &[&[u8]], ctx: &mut ConnContext, timeout: Duration) -> bool {
    match super::sniff_quic::sniff(datagrams) {
        super::sniff_quic::Quic::NoMatch => false,
        super::sniff_quic::Quic::NeedMore => {
            // already QUIC for `protocol` rules; the domain is what is missing
            ctx.protocol = Some("quic".into());
            ctx.sniff_error = Some(SniffError::NeedMore);
            ctx.sniff_timeout = Some(if timeout.is_zero() {
                DEFAULT_SNIFF_TIMEOUT
            } else {
                timeout
            });
            true
        }
        super::sniff_quic::Quic::Hello(sni) => {
            ctx.protocol = Some("quic".into());
            if sni.is_some() {
                ctx.domain = sni;
            }
            true
        }
    }
}

/// Reference `actionSniff` for one TCP connection.
pub(crate) async fn action_sniff<S>(
    client: &mut S,
    ctx: &mut ConnContext,
    configured: &[String],
    timeout: Duration,
) where
    S: AsyncRead + Unpin,
{
    if SKIP_PORTS.contains(&ctx.destination.port()) {
        logging::debug(format_args!(
            "sniff skipped due to port considered as server-first"
        ));
        return;
    }
    if ctx.protocol.is_some() {
        logging::debug(format_args!("duplicate sniff skipped"));
        return;
    }
    let sniffers: Vec<SnifferFn> = if configured.is_empty() {
        default_stream_sniffers()
    } else {
        configured
            .iter()
            .filter_map(|n| sniffer_by_name(n))
            .collect()
    };
    if sniffers.is_empty() {
        // Only packet sniffers configured — nothing to do on TCP.
        return;
    }
    if ctx.sniffer_names.as_slice() == configured
        && matches!(ctx.sniff_error, Some(SniffError::Failed(_)))
    {
        logging::debug(format_args!(
            "sniff skipped due to previous error: {:?}",
            ctx.sniff_error
        ));
        return;
    }

    let timeout = if timeout.is_zero() {
        DEFAULT_SNIFF_TIMEOUT
    } else {
        timeout
    };
    let outcome = peek_stream(client, ctx, timeout, &sniffers).await;
    ctx.sniffer_names = configured.to_vec();
    ctx.sniff_error = outcome.err();
    match &ctx.sniff_error {
        None => {
            if let Some(domain) = &ctx.domain {
                logging::debug(format_args!(
                    "sniffed protocol: {:?}, domain: {domain}",
                    ctx.protocol
                ));
            } else {
                logging::debug(format_args!("sniffed protocol: {:?}", ctx.protocol));
            }
        }
        Some(SniffError::Failed(msg)) => {
            logging::debug(format_args!("sniff failed: {msg}"));
        }
        Some(SniffError::NeedMore) => {}
    }
}

/// Read-once loop with an overall deadline; bytes stay in `ctx.sniff_prefix`.
async fn peek_stream<S>(
    client: &mut S,
    ctx: &mut ConnContext,
    timeout: Duration,
    sniffers: &[SnifferFn],
) -> Result<(), SniffError>
where
    S: AsyncRead + Unpin,
{
    let deadline = Instant::now() + timeout;
    let mut chunk = vec![0u8; 2048];
    let mut sniff_error: Option<SniffError> = None;
    let mut i = 0usize;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let read = tokio::time::timeout(remaining, client.read(&mut chunk)).await;
        match read {
            Ok(Ok(0)) => {
                if i == 0 {
                    return Err(SniffError::Failed("read payload: eof".into()));
                }
                break;
            }
            Ok(Ok(n)) => {
                ctx.sniff_prefix.extend_from_slice(&chunk[..n]);
            }
            Ok(Err(err)) => {
                if i == 0 {
                    return Err(SniffError::Failed(format!("read payload: {err}")));
                }
                break;
            }
            Err(_) => {
                if i == 0 {
                    return Err(SniffError::Failed("read payload: timeout".into()));
                }
                break;
            }
        }
        i += 1;

        // Sniffers only mutate protocol/domain/client, and only on Matched.
        let prefix = std::mem::take(&mut ctx.sniff_prefix);
        let mut any_need_more = false;
        let mut any_no_match = false;
        let mut matched = false;
        for sniffer in sniffers {
            match sniffer(&prefix, ctx) {
                Outcome::Matched => {
                    matched = true;
                    break;
                }
                Outcome::NeedMore => any_need_more = true,
                Outcome::NoMatch => any_no_match = true,
            }
        }
        let matched_len = prefix.len();
        ctx.sniff_prefix = prefix;
        if matched {
            return Ok(());
        }
        if any_need_more {
            sniff_error = Some(SniffError::NeedMore);
        } else if any_no_match {
            sniff_error = Some(SniffError::Failed(format!(
                "no sniffer matched {matched_len} bytes"
            )));
            break;
        } else {
            break;
        }
    }
    Err(sniff_error.unwrap_or(SniffError::Failed("sniff gave up".into())))
}

// ---------------------------------------------------------------------------
// Individual sniffers
// ---------------------------------------------------------------------------

fn sniff_tls(buf: &[u8], ctx: &mut ConnContext) -> Outcome {
    if buf.is_empty() {
        return Outcome::NeedMore;
    }
    if buf[0] != 0x16 {
        return Outcome::NoMatch;
    }
    if buf.len() < 5 {
        return Outcome::NeedMore;
    }
    let rec_len = usize::from(u16::from_be_bytes([buf[3], buf[4]]));
    if buf.len() < 5 + rec_len {
        return Outcome::NeedMore;
    }
    match core_tls::hello::parse_record(buf) {
        Ok(hello) => {
            ctx.protocol = Some("tls".into());
            if !hello.sni.is_empty() {
                ctx.domain = Some(hello.sni);
            }
            Outcome::Matched
        }
        Err(_) => Outcome::NoMatch,
    }
}

const HTTP_METHODS: &[&[u8]] = &[
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"CONNECT ",
    b"PATCH ",
    b"TRACE ",
];

fn http_method_prefix(buf: &[u8]) -> bool {
    if buf.is_empty() {
        return true;
    }
    HTTP_METHODS.iter().any(|m| {
        let n = buf.len().min(m.len());
        buf[..n].eq_ignore_ascii_case(&m[..n])
    })
}

fn sniff_http(buf: &[u8], ctx: &mut ConnContext) -> Outcome {
    if !http_method_prefix(buf) {
        return Outcome::NoMatch;
    }
    let Some(header_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        if buf.len() > 16 * 1024 {
            return Outcome::NoMatch;
        }
        return Outcome::NeedMore;
    };
    let head = &buf[..header_end];
    let text = String::from_utf8_lossy(head);
    let mut lines = text.lines();
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let request_target = parts.next().unwrap_or_default();

    let mut host: Option<String> = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("host")
        {
            host = Some(value.trim().to_string());
            break;
        }
    }
    if host.is_none() && method.eq_ignore_ascii_case("CONNECT") && !request_target.is_empty() {
        host = Some(request_target.to_string());
    }

    ctx.protocol = Some("http".into());
    if let Some(raw) = host {
        let fqdn = strip_authority_port(&raw);
        if !fqdn.is_empty() {
            ctx.domain = Some(fqdn);
        }
    }
    Outcome::Matched
}

/// `host:port` / `[v6]:port` → host part only (Go `ParseSocksaddr().Fqdn`).
fn strip_authority_port(raw: &str) -> String {
    if let Some(rest) = raw.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return rest[..end].to_string();
        }
        return raw.to_string();
    }
    if let Some((h, p)) = raw.rsplit_once(':')
        && p.parse::<u16>().is_ok()
        && !h.contains(':')
    {
        return h.to_string();
    }
    raw.to_string()
}

fn verify_dns_query_header(header: &[u8]) -> bool {
    if header.len() > 2 {
        let is_response = header[2] & 0x80 != 0;
        let opcode = (header[2] >> 3) & 0x0F;
        let authoritative = header[2] & 0x04 != 0;
        let truncated = header[2] & 0x02 != 0;
        if is_response || opcode != 0 || authoritative || truncated {
            return false;
        }
    }
    if header.len() > 3 {
        let recursion_available = header[3] & 0x80 != 0;
        let reserved = header[3] & 0x40 != 0;
        let rcode = header[3] & 0x0F;
        if recursion_available || reserved || rcode != 0 {
            return false;
        }
    }
    if header.len() > 5 && u16::from_be_bytes([header[4], header[5]]) == 0 {
        return false;
    }
    if header.len() > 7 && u16::from_be_bytes([header[6], header[7]]) != 0 {
        return false;
    }
    if header.len() > 9 && u16::from_be_bytes([header[8], header[9]]) != 0 {
        return false;
    }
    true
}

fn sniff_dns_stream(buf: &[u8], ctx: &mut ConnContext) -> Outcome {
    if buf.len() < 2 {
        return Outcome::NeedMore;
    }
    let len = usize::from(u16::from_be_bytes([buf[0], buf[1]]));
    if len < 12 {
        return Outcome::NoMatch;
    }
    if buf.len() < 2 + len {
        return Outcome::NeedMore;
    }
    let packet = &buf[2..2 + len];
    if !verify_dns_query_header(packet) {
        return Outcome::NoMatch;
    }
    if crate::dns::codec::parse_query(packet).is_err() {
        return Outcome::NoMatch;
    }
    ctx.protocol = Some("dns".into());
    Outcome::Matched
}

fn sniff_dns_packet(packet: &[u8], ctx: &mut ConnContext) -> bool {
    if packet.len() < 12
        || !verify_dns_query_header(packet)
        || crate::dns::codec::parse_query(packet).is_err()
    {
        return false;
    }
    ctx.protocol = Some("dns".into());
    true
}

/// RFC 5389 6: the magic cookie, and a body as long as the header says.
fn sniff_stun(p: &[u8], ctx: &mut ConnContext) -> bool {
    if p.len() < 20 || p[4..8] != [0x21, 0x12, 0xa4, 0x42] {
        return false;
    }
    if p.len() < 20 + usize::from(u16::from_be_bytes([p[2], p[3]])) {
        return false;
    }
    ctx.protocol = Some("stun".into());
    true
}

/// BEP 29 uTP: version 1, a known type, and an extension chain that ends.
fn sniff_utp(p: &[u8], ctx: &mut ConnContext) -> bool {
    if p.len() < 20 || p[0] & 0x0f != 1 || p[0] >> 4 > 4 {
        return false;
    }
    let mut extension = p[1];
    let mut pos = 20;
    while extension != 0 {
        let (Some(&next), Some(&len)) = (p.get(pos), p.get(pos + 1)) else {
            return false;
        };
        extension = next;
        pos += 2 + usize::from(len);
    }
    ctx.protocol = Some("bittorrent".into());
    true
}

/// BEP 15 connect request: the protocol id and action 0.
fn sniff_udp_tracker(p: &[u8], ctx: &mut ConnContext) -> bool {
    if p.len() < 16 || p[..8] != 0x0417_2710_1980u64.to_be_bytes() || p[8..12] != [0, 0, 0, 0] {
        return false;
    }
    ctx.protocol = Some("bittorrent".into());
    true
}

/// A DTLS 1.0/1.2 record header.
fn sniff_dtls(p: &[u8], ctx: &mut ConnContext) -> bool {
    if p.len() < 13 || !matches!(p[0], 20..=23 | 25) || p[1] != 0xfe || !matches!(p[2], 0xff | 0xfd)
    {
        return false;
    }
    ctx.protocol = Some("dtls".into());
    true
}

/// An NTPv3/v4 client request whose root delay and dispersion stay under
/// the 16 seconds the reference allows (16.16 fixed point).
fn sniff_ntp(p: &[u8], ctx: &mut ConnContext) -> bool {
    if p.len() < 48 || !matches!((p[0] >> 3) & 7, 3 | 4) || p[0] & 7 != 3 {
        return false;
    }
    let root = |at: usize| u32::from_be_bytes([p[at], p[at + 1], p[at + 2], p[at + 3]]);
    if root(4) > 16 << 16 || root(8) > 16 << 16 {
        return false;
    }
    ctx.protocol = Some("ntp".into());
    true
}

fn sniff_bittorrent(buf: &[u8], ctx: &mut ConnContext) -> Outcome {
    if buf.is_empty() {
        return Outcome::NeedMore;
    }
    if buf[0] != 19 {
        return Outcome::NoMatch;
    }
    const HEADER: &[u8] = b"BitTorrent protocol";
    let n = buf.len().saturating_sub(1).min(HEADER.len());
    if !buf[1..1 + n].eq_ignore_ascii_case(&HEADER[..n]) {
        return Outcome::NoMatch;
    }
    if buf.len() < 20 {
        return Outcome::NeedMore;
    }
    ctx.protocol = Some("bittorrent".into());
    Outcome::Matched
}

fn sniff_ssh(buf: &[u8], ctx: &mut ConnContext) -> Outcome {
    const PREFIX: &[u8] = b"SSH-2.0-";
    if buf.is_empty() {
        return Outcome::NeedMore;
    }
    let n = buf.len().min(PREFIX.len());
    if !buf[..n].eq(&PREFIX[..n]) {
        return Outcome::NoMatch;
    }
    if buf.len() < PREFIX.len() {
        return Outcome::NeedMore;
    }
    let Some(newline) = buf.iter().position(|&b| b == b'\n') else {
        if buf.len() > 1024 {
            return Outcome::NoMatch;
        }
        return Outcome::NeedMore;
    };
    let mut line = &buf[..newline];
    if line.last() == Some(&b'\r') {
        line = &line[..line.len() - 1];
    }
    if line.len() < PREFIX.len() {
        return Outcome::NoMatch;
    }
    ctx.protocol = Some("ssh".into());
    ctx.client = Some(String::from_utf8_lossy(&line[PREFIX.len()..]).into_owned());
    Outcome::Matched
}

fn sniff_rdp(buf: &[u8], ctx: &mut ConnContext) -> Outcome {
    // TPKT(4) + COTP-len(1) + TPDU(1) + skip(5) + type(1) + flags(1) + len(1)
    if buf.is_empty() {
        return Outcome::NeedMore;
    }
    if buf[0] != 0x03 {
        return Outcome::NoMatch;
    }
    if buf.len() < 2 {
        return Outcome::NeedMore;
    }
    if buf[1] != 0x00 {
        return Outcome::NoMatch;
    }
    if buf.len() < 4 {
        return Outcome::NeedMore;
    }
    if u16::from_be_bytes([buf[2], buf[3]]) != 19 {
        return Outcome::NoMatch;
    }
    if buf.len() < 5 {
        return Outcome::NeedMore;
    }
    if buf[4] != 14 {
        return Outcome::NoMatch;
    }
    if buf.len() < 6 {
        return Outcome::NeedMore;
    }
    if buf[5] != 0xE0 {
        return Outcome::NoMatch;
    }
    if buf.len() < 12 {
        return Outcome::NeedMore;
    }
    if buf[11] != 0x01 {
        return Outcome::NoMatch;
    }
    if buf.len() < 14 {
        return Outcome::NeedMore;
    }
    if buf[13] != 8 {
        return Outcome::NoMatch;
    }
    ctx.protocol = Some("rdp".into());
    Outcome::Matched
}
