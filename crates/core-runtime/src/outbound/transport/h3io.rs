//! HTTP/3 CONNECT tunnel over a quinn connection, as raw byte pipes.
//!
//! h3 models a request as a stream object rather than a pair of byte pipes, so
//! this wraps `RequestStream`: reads drain `recv_data`, writes go out through
//! `send_data`, and `finish` is the half-close. The response head is awaited
//! before the first read, and its status gates it, exactly like the h2 path.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use h3::client::RequestStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// One h3 request stream wrapped as raw byte pipes.
pub(crate) struct H3Stream {
    stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    /// The connection's last `SendRequest` must stay alive for as long as the
    /// tunnel does: dropping it trips h3's `Connection closed by client`
    /// internal error, and every later write on this stream fails. The same
    /// hold-the-handle shape lives in `hysteria2::_send_request`.
    _send_request: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    /// Received bytes not yet handed to the caller, chunk by chunk — the
    /// same shape as `h2io`: a chunk is queued as it arrives instead of
    /// being copied into one join buffer (the mistake h2io.rs:54-58
    /// documents). quinn hands `Bytes` over with no copy already.
    pending: VecDeque<Bytes>,
    eof: bool,
    response_read: bool,
}

impl H3Stream {
    pub(crate) async fn new(
        mut stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
        send_request: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
        conn_task: tokio::task::JoinHandle<()>,
    ) -> io::Result<Self> {
        let response = stream
            .recv_response()
            .await
            .map_err(|e| io::Error::other(format!("naive: h3 response: {e}")))?;
        // the h2 path gates the stream on 200, so the h3 one does the same
        if response.status() != http::StatusCode::OK {
            conn_task.abort();
            return Err(io::Error::other(format!(
                "naive: unexpected status: {}",
                response.status()
            )));
        }
        Ok(Self {
            stream,
            _send_request: send_request,
            pending: VecDeque::new(),
            eof: false,
            response_read: true,
        })
    }
}

impl AsyncRead for H3Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if !this.response_read {
            return Poll::Ready(Err(io::Error::other("naive: h3: no response")));
        }
        loop {
            if let Some(front) = this.pending.front_mut() {
                let n = out.remaining().min(front.len());
                out.put_slice(&front[..n]);
                front.advance(n);
                if front.is_empty() {
                    this.pending.pop_front();
                }
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut this.stream).poll_recv_data(cx) {
                Poll::Ready(Ok(Some(mut chunk))) => {
                    let n = chunk.remaining();
                    if n > 0 {
                        // the concrete h3 payload is `Bytes`
                        // (FrameStream::take_chunk hands out a split, no
                        // copy), so copy_to_bytes resolves to Bytes' own
                        // zero-copy split under static dispatch
                        this.pending.push_back(chunk.copy_to_bytes(n));
                    }
                }
                Poll::Ready(Ok(None)) => this.eof = true,
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(io::Error::other(format!("naive: h3 recv: {e}"))));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for H3Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // The copy here is the borrowed `AsyncWrite` boundary itself, not a
        // join: dropping it needs an owned `send_bytes` path through every
        // relay, like A8. Do not "optimize" this one in isolation.
        let mut future = std::pin::pin!(self.stream.send_data(Bytes::copy_from_slice(buf)));
        match Future::poll(future.as_mut(), cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(io::Error::other(format!("naive: h3 send: {e}"))))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut future = std::pin::pin!(self.stream.finish());
        match Future::poll(future.as_mut(), cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(io::Error::other(format!("naive: h3 finish: {e}"))))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
