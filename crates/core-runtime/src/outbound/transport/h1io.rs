//! HTTP/1.1 client plumbing for the transports the reference pins to HTTP/1.1.
//!
//! Hand-rolled for the same reason `transport/http.rs` is: the tree carries no
//! HTTP client crate and the release budget has no room for one. What lives
//! here is only what an HTTP/1.1 client needs and an HTTP/2 stream does not — a
//! request head on the wire, a response head parsed back off it, and the three
//! body framings RFC 9112 §6 defines.
//!
//! One request owns one connection. That is the whole reason this module exists:
//! HTTP/1.1 does not multiplex, so a transport that needs several concurrent
//! requests has to open several connections — and ALPN, which decides what those
//! connections speak, is chosen per connection.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::task::JoinHandle;

use crate::inbound::AnyStream;

/// How a request body is delimited on the way out, and how a response body is
/// delimited on the way back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Framing {
    /// No body at all.
    None,
    /// `Content-Length: n` — exactly n bytes. Reusable after them.
    Length(u64),
    /// `Transfer-Encoding: chunked` — chunks until the zero chunk. Reusable.
    Chunked,
    /// No delimiter: the body runs to the close, so the connection is spent.
    UntilClose,
}

/// The parsed response head.
#[derive(Debug)]
pub(crate) struct Head {
    pub status: u16,
    pub framing: Framing,
    /// The connection cannot carry another request.
    pub close: bool,
}

const MAX_HEAD: usize = 16 * 1024;
const MAX_LINE: usize = 8 * 1024;
const MAX_TRAILER: usize = 16 * 1024;

/// Refuse a response the caller cannot use. The wording is the reference's,
/// because that is what a user comparing two logs will be reading.
pub(crate) fn expect_ok(head: &Head, what: &str) -> io::Result<()> {
    if head.status == 200 {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "v2ray-xhttp: unexpected {what} status: {}",
        head.status
    )))
}

/// Serialize a request head: `METHOD path?query HTTP/1.1`, `Host`, the caller's
/// headers, the framing header, CRLF.
///
/// The URI an [`http::Request`] carries is absolute (`https://host/path`), while
/// HTTP/1.1 wants origin-form on the wire, so the scheme and authority are cut
/// off and the authority goes out as `Host` instead — written first, and any
/// `host` among the caller's own headers skipped, so there is exactly one.
pub(crate) fn write_head(
    out: &mut Vec<u8>,
    request: &http::Request<()>,
    host: &str,
    framing: Framing,
    close: bool,
) {
    let uri = request.uri();
    let target = match uri.query() {
        Some(query) => format!("{}?{}", uri.path(), query),
        None => uri.path().to_string(),
    };
    out.extend_from_slice(request.method().as_str().as_bytes());
    out.push(b' ');
    out.extend_from_slice(target.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");
    out.extend_from_slice(b"Host: ");
    out.extend_from_slice(host.as_bytes());
    out.extend_from_slice(b"\r\n");
    for (name, value) in request.headers() {
        if name.as_str().eq_ignore_ascii_case("host") {
            continue;
        }
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    match framing {
        Framing::None | Framing::UntilClose => {}
        Framing::Length(n) => {
            out.extend_from_slice(format!("Content-Length: {n}\r\n").as_bytes());
        }
        Framing::Chunked => out.extend_from_slice(b"Transfer-Encoding: chunked\r\n"),
    }
    if close {
        out.extend_from_slice(b"Connection: close\r\n");
    }
    out.extend_from_slice(b"\r\n");
}

/// Read a response head, plus whatever body bytes arrived with it.
pub(crate) async fn read_head(io: &mut AnyStream) -> io::Result<(Head, BytesMut)> {
    let mut buf = BytesMut::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        if let Some(end) = head_end(&buf) {
            let head = buf.split_to(end);
            return Ok((parse_head(&head)?, buf));
        }
        if buf.len() > MAX_HEAD {
            return Err(io::Error::other("xhttp: response head too large"));
        }
        if io.read(&mut byte).await? == 0 {
            return Err(io::Error::other(
                "xhttp: connection closed before the response head",
            ));
        }
        buf.extend_from_slice(&byte[..1]);
    }
}

fn head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// `HTTP/1.1 200 OK` plus headers, parsed by hand off the raw head bytes.
fn parse_head(raw: &[u8]) -> io::Result<Head> {
    let text = String::from_utf8_lossy(raw);
    let mut lines = text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| io::Error::other("xhttp: empty response"))?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/1.") {
        return Err(io::Error::other(format!(
            "xhttp: not an HTTP/1.x response: {status_line:?}"
        )));
    }
    let code = parts
        .next()
        .ok_or_else(|| io::Error::other(format!("xhttp: no status code: {status_line:?}")))?;
    let status: u16 = code
        .parse()
        .map_err(|_| io::Error::other(format!("xhttp: bad status code: {code:?}")))?;

    let mut chunked = false;
    let mut content_length: Option<u64> = None;
    let mut close = false;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "transfer-encoding" => {
                chunked = value
                    .to_ascii_lowercase()
                    .split(',')
                    .any(|token| token.trim() == "chunked");
            }
            "content-length" => {
                content_length = Some(value.parse::<u64>().map_err(|_| {
                    io::Error::other(format!("xhttp: bad content-length: {value:?}"))
                })?);
            }
            "connection" => close = value.to_ascii_lowercase().contains("close"),
            _ => {}
        }
    }

    // RFC 9112 §6.3: chunked wins over content-length, a status that forbids a
    // body has none, and anything else runs to the close.
    let bodyless = status == 204 || status == 304 || (100..200).contains(&status);
    let framing = if bodyless {
        Framing::Length(0)
    } else if chunked {
        Framing::Chunked
    } else {
        match content_length {
            Some(n) => Framing::Length(n),
            None => Framing::UntilClose,
        }
    };
    Ok(Head {
        status,
        framing,
        close: close || framing == Framing::UntilClose,
    })
}

/// Where a body reader has got to. `Length`/`Data` count the bytes still owed,
/// everything else is a parsing step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cursor {
    Done,
    Length(u64),
    UntilClose,
    /// chunked: reading a size line
    Size,
    /// chunked: reading `n` more bytes of the current chunk
    Data(u64),
    /// chunked: reading the CRLF that closes a chunk
    Crlf,
    /// chunked: past the zero chunk, reading any trailer fields
    Trailer,
}

/// A response body, framed. Reads hand out whatever arrived; the connection is
/// reusable once the body is drained and the framing allowed it.
pub(crate) struct Body {
    io: AnyStream,
    cursor: Cursor,
    /// body bytes already read past the head
    pending: BytesMut,
    /// the head said the connection is spent, whatever the framing says
    close: bool,
}

impl Body {
    pub(crate) fn new(io: AnyStream, head: &Head, pending: BytesMut) -> Self {
        let cursor = match head.framing {
            Framing::Length(n) => Cursor::Length(n),
            Framing::Chunked => Cursor::Size,
            Framing::UntilClose => Cursor::UntilClose,
            // a request can ask for no body; a response never frames that way
            Framing::None => Cursor::Done,
        };
        Self {
            io,
            cursor,
            pending,
            // a body that runs to the close spends the connection even when the
            // head did not say so
            close: head.close || head.framing == Framing::UntilClose,
        }
    }

    /// Take the connection back out. `None` while the body still owes bytes, and
    /// `None` for a response that said it was closing: handing a socket back
    /// mid-response is how a keep-alive pool ends up serving one response to two
    /// requests. `None` too when bytes past the body are still buffered: they
    /// belong to the next response, and the buffer does not travel with the socket.
    pub(crate) fn into_inner(self) -> Option<AnyStream> {
        (matches!(self.cursor, Cursor::Done) && !self.close && self.pending.is_empty())
            .then_some(self.io)
    }

    /// Read and throw away the rest of the body, so a keep-alive connection can
    /// go back to its pool.
    pub(crate) async fn drain(&mut self) -> io::Result<()> {
        let mut sink = [0u8; 4096];
        while self.cursor != Cursor::Done {
            let n = self.read_some(&mut sink).await?;
            if n == 0 {
                break;
            }
        }
        Ok(())
    }

    /// Hand out as much of `pending` as the cursor owes and the caller has room
    /// for. False means the caller should come back later.
    fn serve(&mut self, out: &mut ReadBuf<'_>) -> bool {
        if self.pending.is_empty() || out.remaining() == 0 {
            return false;
        }
        let owed = match self.cursor {
            Cursor::Length(n) | Cursor::Data(n) => n as usize,
            Cursor::UntilClose => usize::MAX,
            // the buffer holds framing here (a size line, a CRLF, a trailer),
            // not body: it is parsed, never handed out
            Cursor::Done | Cursor::Size | Cursor::Crlf | Cursor::Trailer => return false,
        };
        let n = out.remaining().min(self.pending.len()).min(owed);
        if n == 0 {
            return false;
        }
        out.put_slice(&self.pending[..n]);
        let _ = self.pending.split_to(n);
        match self.cursor {
            Cursor::Length(left) => {
                self.cursor = if left - n as u64 == 0 {
                    Cursor::Done
                } else {
                    Cursor::Length(left - n as u64)
                };
            }
            // a chunk that runs out is not the end of the body: its CRLF is
            // still owed, and then the next size line
            Cursor::Data(left) => {
                self.cursor = if left - n as u64 == 0 {
                    Cursor::Crlf
                } else {
                    Cursor::Data(left - n as u64)
                };
            }
            _ => {}
        }
        true
    }

    /// Pull more bytes, never past what the cursor still owes: a server that
    /// pipelined the next response must not have it eaten here.
    async fn fill(&mut self) -> io::Result<bool> {
        let mut tmp = [0u8; 8192];
        let cap = match self.cursor {
            Cursor::Length(n) | Cursor::Data(n) => (tmp.len() as u64).min(n) as usize,
            Cursor::Done => 0,
            _ => tmp.len(),
        };
        if cap == 0 {
            return Ok(false);
        }
        let n = self.io.read(&mut tmp[..cap]).await?;
        if n == 0 {
            // A counted body cut short is a truncated response, not a clean end;
            // the framings that run to the close may legitimately stop here.
            if let Cursor::Length(left) | Cursor::Data(left) = self.cursor
                && left > 0
            {
                return Err(io::Error::other(format!(
                    "xhttp: response body truncated, {left} bytes missing"
                )));
            }
            self.cursor = Cursor::Done;
            return Ok(false);
        }
        self.pending.extend_from_slice(&tmp[..n]);
        Ok(true)
    }

    /// Read the rest of the body without a `ReadBuf`, which is all `drain`
    /// needs.
    async fn read_some(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        std::future::poll_fn(|cx| {
            let mut out = ReadBuf::new(buf);
            match Pin::new(&mut *self).poll_read(cx, &mut out) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => Poll::Ready(Ok(out.filled().len())),
            }
        })
        .await
    }
}

impl Body {
    /// One chunk size line, read more if it is not buffered yet.
    async fn read_size_line(&mut self) -> io::Result<()> {
        loop {
            if let Some(end) = find_crlf(&self.pending) {
                let line = self.pending.split_to(end).to_vec();
                let _ = self.pending.split_to(2);
                let text = String::from_utf8_lossy(&line);
                let text = text.split(';').next().unwrap_or("").trim();
                if text.is_empty() {
                    // a stray CRLF where a size line was due: keep scanning
                    continue;
                }
                let size = usize::from_str_radix(text, 16)
                    .map_err(|_| io::Error::other(format!("xhttp: chunk size: {text:?}")))?;
                self.cursor = if size == 0 {
                    Cursor::Trailer
                } else {
                    Cursor::Data(size as u64)
                };
                return Ok(());
            }
            if self.pending.len() > MAX_LINE {
                return Err(io::Error::other("xhttp: chunk size line too long"));
            }
            if !self.fill().await? {
                self.cursor = Cursor::Done;
                return Ok(());
            }
        }
    }

    /// The CRLF that closes a chunk.
    async fn read_crlf(&mut self) -> io::Result<()> {
        loop {
            if let Some(end) = find_crlf(&self.pending) {
                let _ = self.pending.split_to(end + 2);
                self.cursor = Cursor::Size;
                return Ok(());
            }
            if self.pending.len() > 8 {
                return Err(io::Error::other("xhttp: junk between chunk and its CRLF"));
            }
            if !self.fill().await? {
                self.cursor = Cursor::Done;
                return Ok(());
            }
        }
    }

    /// Trailer fields after the zero chunk. They have to be consumed even though
    /// nobody reads them: on a keep-alive connection they sit in front of the
    /// next response, and a parser that starts on them reads a status line out
    /// of a header field.
    async fn read_trailer(&mut self) -> io::Result<()> {
        loop {
            if self.pending.starts_with(b"\r\n") {
                let _ = self.pending.split_to(2);
                self.cursor = Cursor::Done;
                return Ok(());
            }
            if let Some(end) = head_end(&self.pending) {
                let _ = self.pending.split_to(end);
                self.cursor = Cursor::Done;
                return Ok(());
            }
            if self.pending.len() > MAX_TRAILER {
                return Err(io::Error::other("xhttp: trailer too large"));
            }
            if !self.fill().await? {
                self.cursor = Cursor::Done;
                return Ok(());
            }
        }
    }
}

impl AsyncRead for Body {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // The reader is a plain async loop, pinned and polled by hand, so the
        // `?`s live in an ordinary function. Rebuilding the future on every
        // poll loses nothing: all of its state is in `cursor` and `pending`,
        // which live in the body itself.
        let body = &mut *self;
        let reader = async move {
            loop {
                if body.serve(out) {
                    return Ok(());
                }
                match body.cursor {
                    Cursor::Done => return Ok(()),
                    Cursor::Size => body.read_size_line().await?,
                    Cursor::Crlf => body.read_crlf().await?,
                    Cursor::Trailer => body.read_trailer().await?,
                    Cursor::Length(_) | Cursor::Data(_) | Cursor::UntilClose => {
                        if !body.fill().await? {
                            return Ok(());
                        }
                    }
                }
            }
        };
        std::pin::pin!(reader).poll(cx)
    }
}

impl AsyncWrite for Body {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::other("xhttp: response body is read-only")))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

/// One-shot exchange: write the request with a `Content-Length` body, then read
/// the response head. The body is handed back unconsumed — the caller wraps it
/// into a [`Body`] when it wants the bytes (a download) and drains it when it
/// only wants the connection back (an upload).
pub(crate) async fn send(
    io: &mut AnyStream,
    request: &http::Request<()>,
    host: &str,
    body: &[u8],
    close: bool,
) -> io::Result<(Head, BytesMut)> {
    let framing = if body.is_empty() {
        Framing::None
    } else {
        Framing::Length(body.len() as u64)
    };
    let mut head = Vec::with_capacity(256);
    write_head(&mut head, request, host, framing, close);
    io.write_all(&head).await?;
    if !body.is_empty() {
        io.write_all(body).await?;
    }
    io.flush().await?;
    read_head(io).await
}

/// Chunked framing for one body write: `<hex len>\r\n<payload>\r\n`.
pub(crate) fn chunk(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 16);
    out.extend_from_slice(format!("{:x}\r\n", payload.len()).as_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(b"\r\n");
    out
}

/// The terminating chunk of a chunked body.
pub(crate) const LAST_CHUNK: &[u8] = b"0\r\n\r\n";

/// The write half of a streamed request: the head goes out at `start`, then
/// every write is one chunk. The read half is pumped by the task this hands
/// back, so a response can arrive while the body is still going up — which is
/// the whole point of the streamed modes.
pub(crate) struct Stream {
    io: tokio::io::WriteHalf<AnyStream>,
    /// one staged chunk not yet written to the socket
    out: Vec<u8>,
    pos: usize,
    /// caller bytes the staged chunk accounts for, reported once it is out
    report: usize,
    ended: bool,
}

impl Stream {
    pub(crate) async fn start(
        io: AnyStream,
        request: &http::Request<()>,
        host: &str,
        close: bool,
    ) -> io::Result<(Self, JoinHandle<io::Result<Body>>)> {
        let mut head = Vec::with_capacity(256);
        write_head(&mut head, request, host, Framing::Chunked, close);
        let (reader, mut writer) = tokio::io::split(io);
        writer.write_all(&head).await?;
        writer.flush().await?;
        let mut reader: AnyStream = Box::new(ReadHalf(reader));
        let task = tokio::spawn(async move {
            let (head, pending) = read_head(&mut reader).await?;
            expect_ok(&head, "upload")?;
            Ok(Body::new(reader, &head, pending))
        });
        Ok((
            Self {
                io: writer,
                out: Vec::new(),
                pos: 0,
                report: 0,
                ended: false,
            },
            task,
        ))
    }

    fn flush_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pos < self.out.len() {
            let n = ready!(Pin::new(&mut self.io).poll_write(cx, &self.out[self.pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::other("xhttp: chunk write stalled")));
            }
            self.pos += n;
        }
        self.out.clear();
        self.pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.ended {
            return Poll::Ready(Err(io::Error::other("xhttp: stream already ended")));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // a partly written chunk keeps its staging, because poll_write is
        // always retried with the same buffer
        if this.pos >= this.out.len() {
            this.out = chunk(buf);
            this.pos = 0;
            this.report = buf.len();
        }
        ready!(this.flush_out(cx))?;
        Poll::Ready(Ok(std::mem::take(&mut this.report)))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.flush_out(cx))?;
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if !this.ended {
            this.ended = true;
            this.out = LAST_CHUNK.to_vec();
            this.pos = 0;
            this.report = 0;
        }
        ready!(this.flush_out(cx))?;
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

/// `tokio::io::ReadHalf` is `AsyncRead` but not `AsyncWrite`, and `read_head`
/// wants the combined `AnyStream`. This is the write side it does not have.
struct ReadHalf(tokio::io::ReadHalf<AnyStream>);

impl AsyncRead for ReadHalf {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, out)
    }
}

impl AsyncWrite for ReadHalf {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::other("xhttp: split read half cannot write")))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(raw: &[u8]) -> io::Result<Head> {
        parse_head(raw)
    }

    #[test]
    fn request_head_is_origin_form_with_one_host() {
        let request = http::Request::builder()
            .method("POST")
            .uri("https://node.example:443/xh/SID/7?x_padding=00")
            .header("X-Test", "1")
            .body(())
            .unwrap();
        let mut out = Vec::new();
        write_head(
            &mut out,
            &request,
            "node.example:443",
            Framing::Length(4),
            false,
        );
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.starts_with("POST /xh/SID/7?x_padding=00 HTTP/1.1\r\n"),
            "got {text:?}"
        );
        assert!(text.contains("\r\nHost: node.example:443\r\n"));
        assert_eq!(text.matches("\r\nHost: ").count(), 1);
        assert!(text.contains("\r\nx-test: 1\r\n"), "got {text:?}");
        assert!(text.contains("\r\nContent-Length: 4\r\n"));
        assert!(!text.contains("Transfer-Encoding"));
        assert!(!text.contains("Connection: close"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn a_callers_host_header_does_not_double_up() {
        let request = http::Request::builder()
            .method("GET")
            .uri("https://a.example/p")
            .header("host", "b.example")
            .body(())
            .unwrap();
        let mut out = Vec::new();
        write_head(&mut out, &request, "a.example", Framing::None, true);
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.matches("ost:").count(), 1, "got {text:?}");
        assert!(text.contains("Connection: close\r\n"));
    }

    #[test]
    fn response_framing_follows_the_head() {
        let h = head(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n").expect("head");
        assert_eq!(h.status, 200);
        assert_eq!(h.framing, Framing::Length(5));
        assert!(!h.close, "a counted body leaves the connection reusable");

        let h = head(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n").expect("head");
        assert_eq!(h.framing, Framing::Chunked);
        assert!(!h.close);

        let h = head(b"HTTP/1.1 200 OK\r\n\r\n").expect("head");
        assert_eq!(h.framing, Framing::UntilClose);
        assert!(
            h.close,
            "a body that runs to the close spends the connection"
        );

        let h = head(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            .expect("head");
        assert!(h.close);
    }

    #[test]
    fn chunked_wins_over_content_length() {
        let h = head(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nTransfer-Encoding: chunked\r\n\r\n")
            .expect("head");
        assert_eq!(h.framing, Framing::Chunked);
    }

    #[test]
    fn a_status_that_forbids_a_body_has_none() {
        let h = head(b"HTTP/1.1 204 No Content\r\n\r\n").expect("head");
        assert_eq!(h.framing, Framing::Length(0));
    }

    #[test]
    fn a_broken_head_is_refused_by_name() {
        assert!(head(b"garbage\r\n\r\n").is_err());
        assert!(head(b"HTTP/1.1 abc OK\r\n\r\n").is_err());
        let e = head(b"HTTP/1.1 200 OK\r\nContent-Length: many\r\n\r\n")
            .expect_err("bad length")
            .to_string();
        assert!(e.contains("content-length"), "got {e}");
    }

    #[test]
    fn expect_ok_names_what_it_was_waiting_for() {
        let refused = Head {
            status: 403,
            framing: Framing::Length(0),
            close: false,
        };
        let e = expect_ok(&refused, "upload")
            .expect_err("refused")
            .to_string();
        assert_eq!(e, "v2ray-xhttp: unexpected upload status: 403");
        let fine = Head {
            status: 200,
            framing: Framing::Length(0),
            close: false,
        };
        assert!(expect_ok(&fine, "upload").is_ok());
    }

    #[test]
    fn chunk_framing_is_hex_length_then_crlf() {
        assert_eq!(chunk(b"ping"), b"4\r\nping\r\n".to_vec());
        assert_eq!(chunk(b""), b"0\r\n\r\n".to_vec());
        assert_eq!(chunk(&[0u8; 256]), {
            let mut want = b"100\r\n".to_vec();
            want.extend_from_slice(&[0u8; 256]);
            want.extend_from_slice(b"\r\n");
            want
        });
    }

    /// A body reader over a scripted byte stream: everything the script does not
    /// cover is EOF, which is enough to prove the framing — what the reader
    /// hands out, and when it says the connection is whole again.
    fn body_of(framing: Framing, script: &[u8]) -> Body {
        let head = Head {
            status: 200,
            framing,
            close: false,
        };
        let (io, peer) = tokio::io::duplex(1);
        drop(peer);
        Body::new(Box::new(WriteOnly(io)), &head, BytesMut::from(script))
    }

    /// The read side of a body under test is always EOF: the script is the body.
    struct WriteOnly<T>(T);

    impl<T: AsyncWrite + Unpin> AsyncRead for WriteOnly<T> {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            out: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            out.advance(0);
            Poll::Ready(Ok(()))
        }
    }

    impl<T: AsyncWrite + Unpin> AsyncWrite for WriteOnly<T> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn a_counted_body_hands_out_exactly_that_many_bytes() {
        let mut body = body_of(Framing::Length(5), b"hello world");
        let mut out = [0u8; 32];
        let n = body.read(&mut out).await.expect("read");
        assert_eq!(&out[..n], b"hello");
        // " world" is past the body: it belongs to the next response, and the
        // buffer it sits in does not go back to a pool with the socket
        assert!(body.into_inner().is_none());
        let mut whole = body_of(Framing::Length(5), b"hello");
        let n = whole.read(&mut out).await.expect("read");
        assert_eq!(&out[..n], b"hello");
        assert!(whole.into_inner().is_some(), "nothing owed, reusable");
    }

    #[tokio::test]
    async fn a_counted_body_cut_short_is_an_error() {
        let mut body = body_of(Framing::Length(10), b"hi");
        let e = body.drain().await.expect_err("truncated");
        assert!(e.to_string().contains("truncated"), "got {e}");
    }

    #[tokio::test]
    async fn a_chunked_body_is_reassembled_and_its_trailer_eaten() {
        let mut body = body_of(Framing::Chunked, b"4\r\nping\r\n0\r\nX-T: v\r\n\r\n");
        let mut out = [0u8; 32];
        let n = body.read(&mut out).await.expect("read");
        assert_eq!(&out[..n], b"ping");
        // the trailer fields are nobody's business but must still be consumed:
        // on a keep-alive connection they sit in front of the next response
        body.drain().await.expect("drain");
        assert!(
            body.into_inner().is_some(),
            "the zero chunk and its trailer end the body"
        );
    }

    #[tokio::test]
    async fn a_body_with_no_delimiter_ends_at_the_close_and_spends_the_connection() {
        let mut body = body_of(Framing::UntilClose, b"anything at all");
        let mut out = [0u8; 64];
        let n = body.read(&mut out).await.expect("read");
        assert_eq!(&out[..n], b"anything at all");
        assert!(body.read(&mut out).await.expect("eof") == 0);
        assert!(
            body.into_inner().is_none(),
            "a body that ran to the close leaves nothing to reuse"
        );
    }

    #[tokio::test]
    async fn drain_leaves_a_keep_alive_connection_whole() {
        let mut body = body_of(Framing::Length(4), b"body");
        body.drain().await.expect("drain");
        assert!(body.into_inner().is_some());
    }
}
