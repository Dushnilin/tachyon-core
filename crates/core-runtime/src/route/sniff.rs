//! Stream protocol sniffing (TLS / HTTP / DNS / BitTorrent / SSH / RDP)
//! with sing-box `PeekStream` semantics: accumulate payload under a deadline,
//! re-run sniffers on the full prefix, replay the prefix upstream afterwards.

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
