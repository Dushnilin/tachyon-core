//! A stream whose TLS is ours: a captured fingerprint's ClientHello, our own
//! handshake, and application data through our own record layer.
//!
//! The adapter is thin on purpose. `core_tls::client::Connection` works on
//! bytes -- plaintext in, one record out -- so all this has to do is move bytes
//! between the socket and those two calls without ever blocking inside a poll.
//! The blocking parts of the TLS live in core-tls, where they can be tested
//! against a real server; here there is only a buffer and two state flags.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use core_tls::client::Connection;

/// How much to pull off the socket at once. A record is at most 2^14 + 256
/// bytes with its tag, so this reads a whole one in a single go on any socket
/// that is not pathological.
const CHUNK: usize = 18 * 1024;

/// TLS over `S`, established by us rather than by a library.
pub struct FingerprintStream<S> {
    inner: S,
    connection: Connection,
    /// transport bytes that do not make a whole record yet
    raw: Vec<u8>,
    /// plaintext of a record bigger than the buffer a reader brought, and how much
    /// of it has been handed over
    pending: Vec<u8>,
    pending_at: usize,
    /// a record waiting to go out, and how much of it has been written
    out: Option<(Vec<u8>, usize)>,
    eof: bool,
}

impl<S> FingerprintStream<S> {
    /// Wrap a transport whose handshake is already finished.
    pub fn new(inner: S, connection: Connection) -> Self {
        FingerprintStream {
            inner,
            connection,
            raw: Vec::new(),
            pending: Vec::new(),
            pending_at: 0,
            out: None,
            eof: false,
        }
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for FingerprintStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            // plaintext left over from a record the reader's buffer could not
            // take whole
            if me.pending_at < me.pending.len() {
                let take = (me.pending.len() - me.pending_at).min(buf.remaining());
                buf.put_slice(&me.pending[me.pending_at..me.pending_at + take]);
                me.pending_at += take;
                if me.pending_at == me.pending.len() {
                    me.pending.clear();
                    me.pending_at = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if me.eof || me.connection.is_closed() {
                return Poll::Ready(Ok(()));
            }
            // Whatever we already hold comes first, and only then the socket.
            // The order matters: a socket hands us half a record all the time, so
            // "five bytes buffered" says nothing about whether a record is whole.
            // Asking the socket only when the buffer was *short* meant a split
            // record left us spinning over the same bytes forever, never reading
            // the rest of it -- which is what a REALITY server's post-handshake
            // ticket is.
            let data = match me.connection.read_record_from(&mut me.raw) {
                Ok(data) => data,
                Err(e) => return Poll::Ready(Err(e)),
            };
            if !data.is_empty() {
                me.pending = data;
                me.pending_at = 0;
                continue;
            }
            let mut chunk = [0u8; CHUNK];
            let mut read = ReadBuf::new(&mut chunk);
            match Pin::new(&mut me.inner).poll_read(cx, &mut read) {
                Poll::Ready(Ok(())) => {
                    let filled = read.filled();
                    if filled.is_empty() {
                        me.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    me.raw.extend_from_slice(filled);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for FingerprintStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        // A writer that reports writing a 22-byte tag has not written is lying
        // about its input, and every caller that respects the contract -- tokio's
        // `write_all` above all -- slices its buffer by the number it is given.
        // An empty write is nothing to seal: reporting zero for it is the honest
        // answer, and it keeps a caller from sealing an empty record.
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let taken = buf.len();
        loop {
            let Some((record, written)) = me.out.as_mut() else {
                // one record per call: a caller with more writes again, and the
                // sequence number moves with each record, not with each call
                let record = match me.connection.write_record(buf) {
                    Ok(record) => record,
                    Err(e) => return Poll::Ready(Err(e)),
                };
                me.out = Some((record, 0));
                continue;
            };
            match Pin::new(&mut me.inner).poll_write(cx, &record[*written..]) {
                Poll::Ready(Ok(n)) => {
                    *written += n;
                    if *written == record.len() {
                        me.out = None;
                        return Poll::Ready(Ok(taken));
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // poll_write only returns Ready once a record is whole, so there is
        // never a part-written record to flush around
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        me.eof = true;
        Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}

/// One read has to be able to hold a whole record, or every record costs two
/// syscalls: 2^14 of plaintext, a type byte, a 16-byte tag, a 5-byte header.
/// A compile-time check, because a runtime one would only ever be a comment.
const _: () = assert!(CHUNK > 16384 + 1 + 16 + 5);
