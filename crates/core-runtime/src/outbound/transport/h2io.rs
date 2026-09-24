//! Shared HTTP/2 client plumbing for the grpc and http transports:
//! handshake + connection task, response-status gate on first read,
//! flow-controlled writes, and receive-buffer management.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes, BytesMut};
use h2::RecvStream;
use h2::client::ResponseFuture;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::JoinHandle;

/// One HTTP/2 request/response stream wrapped as raw byte pipes.
pub(super) struct H2Stream {
    send: Option<h2::SendStream<Bytes>>,
    response: Option<Pin<Box<ResponseFuture>>>,
    recv: Option<RecvStream>,
    /// Received bytes not yet handed to the caller.
    pub(super) pending: BytesMut,
    /// Encoded bytes waiting on flow-control capacity.
    out: Vec<u8>,
    out_pos: usize,
    report: usize,
    eof: bool,
    conn_task: JoinHandle<()>,
}

impl H2Stream {
    pub(super) fn new(
        response: ResponseFuture,
        send: h2::SendStream<Bytes>,
        conn_task: JoinHandle<()>,
    ) -> Self {
        Self {
            send: Some(send),
            response: Some(Box::pin(response)),
            recv: None,
            pending: BytesMut::new(),
            out: Vec::new(),
            out_pos: 0,
            report: 0,
            eof: false,
            conn_task,
        }
    }

    pub(super) fn has_out(&self) -> bool {
        self.out_pos < self.out.len()
    }

    /// Queue `frame` bytes for transmission; `report` is returned to the
    /// AsyncWrite caller once the whole frame has been accepted.
    pub(super) fn stage(&mut self, frame: Vec<u8>, report: usize) {
        debug_assert!(!self.has_out());
        self.out = frame;
        self.out_pos = 0;
        self.report = report;
    }

    pub(super) fn take_report(&mut self) -> usize {
        std::mem::replace(&mut self.report, 0)
    }

    /// Flush staged bytes as flow control allows; clears `out` when done.
    pub(super) fn poll_flush_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if self.out_pos >= self.out.len() {
                self.out.clear();
                self.out_pos = 0;
                return Poll::Ready(Ok(()));
            }
            let Some(send) = self.send.as_mut() else {
                return Poll::Ready(Err(io::Error::other("h2: stream send side closed")));
            };
            let remaining = self.out.len() - self.out_pos;
            send.reserve_capacity(remaining);
            let cap = match ready!(send.poll_capacity(cx)) {
                Some(Ok(cap)) => cap,
                Some(Err(e)) => {
                    return Poll::Ready(Err(io::Error::other(format!("h2: capacity: {e}"))));
                }
                None => {
                    return Poll::Ready(Err(io::Error::other("h2: stream closed for writing")));
                }
            };
            if cap == 0 {
                continue;
            }
            let n = cap.min(remaining);
            let chunk = Bytes::copy_from_slice(&self.out[self.out_pos..self.out_pos + n]);
            send.send_data(chunk, false)
                .map_err(|e| io::Error::other(format!("h2: send_data: {e}")))?;
            self.out_pos += n;
        }
    }

    /// Wait for the next received chunk into `pending`.
    /// `Ok(false)` means the response body ended (EOF latched).
    pub(super) fn poll_recv_more(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        if self.recv.is_none() {
            let Some(response) = self.response.as_mut() else {
                // Response already consumed; recv stream exhausted.
                self.eof = true;
                return Poll::Ready(Ok(false));
            };
            let resp = match ready!(response.as_mut().poll(cx)) {
                Ok(resp) => resp,
                Err(e) => {
                    return Poll::Ready(Err(io::Error::other(format!("h2: response: {e}"))));
                }
            };
            if resp.status().as_u16() != 200 {
                return Poll::Ready(Err(io::Error::other(format!(
                    "h2: unexpected status: {}",
                    resp.status()
                ))));
            }
            self.recv = Some(resp.into_body());
            self.response = None;
        }
        let recv = self.recv.as_mut().expect("recv set above");
        match ready!(recv.poll_data(cx)) {
            Some(Ok(chunk)) => {
                let len = chunk.len();
                let _ = recv.flow_control().release_capacity(len);
                self.pending.extend_from_slice(&chunk);
                Poll::Ready(Ok(true))
            }
            Some(Err(e)) => Poll::Ready(Err(io::Error::other(format!("h2: recv: {e}")))),
            None => {
                self.eof = true;
                Poll::Ready(Ok(false))
            }
        }
    }

    pub(super) fn is_eof(&self) -> bool {
        self.eof
    }

    /// Half-close: flush staged bytes, then END_STREAM on the send side.
    pub(super) fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_flush_out(cx))?;
        if let Some(mut send) = self.send.take()
            && let Err(e) = send.send_data(Bytes::new(), true)
        {
            return Poll::Ready(Err(io::Error::other(format!("h2: end stream: {e}"))));
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for H2Stream {
    fn drop(&mut self) {
        if let Some(mut send) = self.send.take() {
            send.send_reset(h2::Reason::CANCEL);
        }
        self.conn_task.abort();
    }
}

/// Serve `buf`-style state machines over [`H2Stream`]: reads drain `pending`,
/// writes go through stage + flush. Used directly by the http (h2) transport.
pub(super) struct H2Io {
    pub(super) h2: H2Stream,
}

impl AsyncRead for H2Io {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.h2.pending.is_empty() {
                let n = out.remaining().min(self.h2.pending.len());
                out.put_slice(&self.h2.pending[..n]);
                self.h2.pending.advance(n);
                return Poll::Ready(Ok(()));
            }
            if self.h2.is_eof() {
                return Poll::Ready(Ok(()));
            }
            ready!(self.h2.poll_recv_more(cx))?;
        }
    }
}

impl AsyncWrite for H2Io {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.h2.has_out() {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            self.h2.stage(buf.to_vec(), buf.len());
        }
        ready!(self.h2.poll_flush_out(cx))?;
        Poll::Ready(Ok(self.h2.take_report()))
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.h2.poll_flush_out(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.h2.poll_shutdown(cx)
    }
}
