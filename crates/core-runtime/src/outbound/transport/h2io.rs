//! Shared HTTP/2 client plumbing for the grpc and http transports:
//! handshake + connection task, response-status gate on first read,
//! flow-controlled writes, and receive-buffer management.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes};
use h2::RecvStream;
use h2::client::ResponseFuture;
use http::Response;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::JoinHandle;

/// Receive window per stream and per connection: 16 MiB a stream, 64 MiB a
/// connection, sized to sustain 20+ Gbps transfers without ballooning
/// client RSS across concurrent pooled connections. The window is also the
/// memory ceiling for whatever a fast peer has in flight to a slow reader.
const STREAM_WINDOW: u32 = 16 << 20;
const CONN_WINDOW: u32 = 64 << 20;
/// Largest DATA frame we ask the peer to send.
const MAX_FRAME: u32 = 256 * 1024;

/// The client handshake every h2-based transport shares, with windows sized
/// for throughput.
pub(crate) fn client_builder() -> h2::client::Builder {
    let mut builder = h2::client::Builder::new();
    builder
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONN_WINDOW)
        .max_frame_size(MAX_FRAME)
        .max_send_buffer_size(16 << 20);
    builder
}

/// The server half of the same handshake: same windows, so a server this side
/// runs is measured against the same conditions the client half asks for.
pub(crate) fn server_builder() -> h2::server::Builder {
    let mut builder = h2::server::Builder::new();
    builder
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONN_WINDOW)
        .max_frame_size(MAX_FRAME)
        .max_send_buffer_size(4 << 20);
    builder
}

/// One HTTP/2 request/response stream wrapped as raw byte pipes.
pub(crate) struct H2Stream {
    send: Option<h2::SendStream<Bytes>>,
    response: Option<Pin<Box<ResponseFuture>>>,
    recv: Option<RecvStream>,
    /// Received bytes not yet handed to the caller, chunk by chunk. A new
    /// h2 DATA chunk is pushed as it arrives: the receive path never joins
    /// chunks into one buffer, which used to allocate and copy both sides
    /// of the join whenever a frame header straddled two chunks -- on a
    /// bulk transfer that is a megabyte copied and freed per boundary.
    pub(crate) pending: VecDeque<Bytes>,
    /// Total bytes across `pending`; kept so the readers do not walk the
    /// deque for a length.
    pub(crate) pending_len: usize,
    /// Encoded bytes waiting on flow-control capacity.
    out: Bytes,
    report: usize,
    eof: bool,
    /// `None` when a shared owner drives the connection, as mux does
    conn_task: Option<JoinHandle<()>>,
}

impl H2Stream {
    pub(crate) fn new(
        response: ResponseFuture,
        send: h2::SendStream<Bytes>,
        conn_task: JoinHandle<()>,
    ) -> Self {
        Self::build(response, send, Some(conn_task))
    }

    /// A stream that borrows a connection task owned by a session pool.
    pub(crate) fn shared(response: ResponseFuture, send: h2::SendStream<Bytes>) -> Self {
        Self::build(response, send, None)
    }

    /// The same, for a caller that has already read the head -- naive does, so
    /// that a refused CONNECT is reported as itself rather than as a stream that
    /// happens to be closed. The body is left live even if the head came with an
    /// end-of-stream flag: a CONNECT response that says so is the server's
    /// mistake, and treating it as EOF would drop a tunnel that is still open.
    pub(crate) fn from_response(
        response: Response<RecvStream>,
        send: h2::SendStream<Bytes>,
        conn_task: Option<JoinHandle<()>>,
    ) -> Self {
        Self {
            send: Some(send),
            response: None,
            recv: Some(response.into_body()),
            pending: VecDeque::new(),
            pending_len: 0,
            out: Bytes::new(),
            report: 0,
            eof: false,
            conn_task,
        }
    }

    /// The server side of a stream: the request body arrived with the request
    /// and the response side is already open, so there is no response future to
    /// wait for -- the status gate in [`H2Stream::poll_recv_more`] never runs.
    /// There is no connection task to own either: the connection outlives the
    /// stream (a client that pools connections comes back for the next one), and
    /// the accept loop that hands these out is what drives it, so dropping a
    /// session must not take the connection down with it.
    pub(crate) fn server(recv: RecvStream, send: h2::SendStream<Bytes>) -> Self {
        Self::from_response(Response::new(recv), send, None)
    }

    fn build(
        response: ResponseFuture,
        send: h2::SendStream<Bytes>,
        conn_task: Option<JoinHandle<()>>,
    ) -> Self {
        Self {
            send: Some(send),
            response: Some(Box::pin(response)),
            recv: None,
            pending: VecDeque::new(),
            pending_len: 0,
            out: Bytes::new(),
            report: 0,
            eof: false,
            conn_task,
        }
    }

    pub(crate) fn has_out(&self) -> bool {
        !self.out.is_empty()
    }

    /// Copy up to `max` pending bytes into `out` and return how many went.
    pub(crate) fn serve(&mut self, out: &mut ReadBuf<'_>, max: usize) -> usize {
        let mut left = out.remaining().min(max).min(self.pending_len);
        let want = left;
        while left > 0 {
            let Some(front) = self.pending.front_mut() else {
                break;
            };
            let take = front.len().min(left);
            out.put_slice(&front[..take]);
            front.advance(take);
            self.pending_len -= take;
            left -= take;
            if front.is_empty() {
                self.pending.pop_front();
            }
        }
        let went = want - left;
        self.release(went);
        went
    }

    /// Repay `n` bytes that left `pending`. The window is only repaid when
    /// bytes actually leave our buffer: advertising buffered-but-unread data
    /// tells the peer it may keep sending into a reader that stopped, and
    /// the connection half of the window is shared with the pooled session.
    pub(crate) fn release(&mut self, n: usize) {
        if n > 0
            && let Some(recv) = self.recv.as_mut()
        {
            let _ = recv.flow_control().release_capacity(n);
        }
    }

    /// Drop `n` pending bytes without copying them.
    pub(crate) fn skip_pending(&mut self, mut n: usize) {
        let start = n;
        while n > 0 {
            let Some(front) = self.pending.front_mut() else {
                break;
            };
            let take = front.len().min(n);
            front.advance(take);
            self.pending_len -= take;
            n -= take;
            if front.is_empty() {
                self.pending.pop_front();
            }
        }
        self.release(start - n);
    }

    /// Queue `frame` bytes for transmission; `report` is returned to the
    /// AsyncWrite caller once the whole frame has been accepted.
    ///
    /// The `Vec -> Bytes` here is the borrowed-to-owned boundary of
    /// `AsyncWrite`, not a join: `poll_write` receives `&[u8]` and the h2
    /// layer needs an owned `Bytes` for `SendStream`. Taking `Bytes` in
    /// this signature would save nothing (the caller would build the same
    /// `Bytes` at the same cost); removing the copy altogether needs an
    /// owned `send_bytes` path through the relay layer, which is a relay
    /// rewrite for about one percent of CPU. Keep this comment honest
    /// instead of "optimizing" the call site.
    pub(crate) fn stage(&mut self, frame: Vec<u8>, report: usize) {
        debug_assert!(!self.has_out());
        self.out = Bytes::from(frame);
        self.report = report;
    }

    pub(crate) fn take_report(&mut self) -> usize {
        std::mem::replace(&mut self.report, 0)
    }

    /// Flush staged bytes as flow control allows; clears `out` when done.
    pub(crate) fn poll_flush_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if self.out.is_empty() {
                return Poll::Ready(Ok(()));
            }
            let Some(send) = self.send.as_mut() else {
                return Poll::Ready(Err(io::Error::other("h2: stream send side closed")));
            };
            let remaining = self.out.len();
            send.reserve_capacity(remaining);
            let cap = match send.poll_capacity(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(cap))) => cap,
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::other(format!("h2: capacity: {e}"))));
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::other("h2: stream closed for writing")));
                }
            };
            if cap == 0 {
                continue;
            }
            let chunk = self.out.split_to(cap.min(remaining));
            send.send_data(chunk, false)
                .map_err(|e| io::Error::other(format!("h2: send_data: {e}")))?;
        }
    }

    /// Wait for the next received chunk into `pending`.
    /// `Ok(false)` means the response body ended (EOF latched).
    pub(crate) fn poll_recv_more(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
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
        match recv.poll_data(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Ok(chunk))) => {
                let len = chunk.len();
                // pushed as it arrived: no join, no copy of either side.
                // Capacity is repaid when the bytes leave `pending`, not
                // while we are still holding them.
                self.pending.push_back(chunk);
                self.pending_len += len;
                Poll::Ready(Ok(true))
            }
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Err(io::Error::other(format!("h2: recv: {e}"))))
            }
            Poll::Ready(None) => {
                self.eof = true;
                Poll::Ready(Ok(false))
            }
        }
    }

    pub(crate) fn is_eof(&self) -> bool {
        self.eof
    }

    /// Read into `out`, draining `pending` and pulling all available chunks
    /// from `recv` without blocking before returning. Returns `Ready(Ok(()))` if any
    /// bytes were placed into `out` or if EOF was reached. Returns `Pending` only if
    /// no bytes could be read and the stream is not at EOF.
    pub(crate) fn poll_read_into(
        &mut self,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let initial_filled = out.filled().len();
        loop {
            if !self.pending.is_empty() {
                self.serve(out, usize::MAX);
                if out.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
            }

            if self.eof {
                return Poll::Ready(Ok(()));
            }

            if self.recv.is_none() {
                let Some(response) = self.response.as_mut() else {
                    self.eof = true;
                    return Poll::Ready(Ok(()));
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
            match recv.poll_data(cx) {
                Poll::Ready(Some(Ok(mut chunk))) => {
                    let len = chunk.len();
                    let want = out.remaining();
                    // Only what reaches the caller right now is repaid; the
                    // tail waits in `pending` and is repaid by `serve`.
                    let served = want.min(len);
                    if served > 0 {
                        let _ = recv.flow_control().release_capacity(served);
                    }
                    if want >= len {
                        out.put_slice(&chunk);
                    } else if want > 0 {
                        out.put_slice(&chunk[..want]);
                        chunk.advance(want);
                        self.pending_len += chunk.len();
                        self.pending.push_back(chunk);
                        return Poll::Ready(Ok(()));
                    } else {
                        self.pending_len += len;
                        self.pending.push_back(chunk);
                        return Poll::Ready(Ok(()));
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::other(format!("h2: recv: {e}"))));
                }
                Poll::Ready(None) => {
                    self.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => {
                    if out.filled().len() > initial_filled {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Pending;
                }
            }
        }
    }

    /// Half-close: flush staged bytes, then END_STREAM on the send side.
    pub(crate) fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
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
        // Whatever is still in `pending` was counted against the shared
        // connection window: repay it, or a stream dropped with an unread
        // body shrinks the window the pooled session runs on for good.
        let unread = self.pending_len;
        self.release(unread);
        if let Some(mut send) = self.send.take() {
            send.send_reset(h2::Reason::CANCEL);
        }
        if let Some(task) = self.conn_task.take() {
            task.abort();
        }
    }
}

/// Serve `buf`-style state machines over [`H2Stream`]: reads drain `pending`,
/// writes go through stage + flush. Used directly by the http (h2) transport.
pub(crate) struct H2Io {
    pub(crate) h2: H2Stream,
}

impl AsyncRead for H2Io {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.h2.poll_read_into(cx, out)
    }
}

impl AsyncWrite for H2Io {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.h2.has_out() {
            ready!(self.h2.poll_flush_out(cx))?;
            return Poll::Ready(Ok(self.h2.take_report()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let Some(send) = self.h2.send.as_mut() else {
            return Poll::Ready(Err(io::Error::other("h2: stream send side closed")));
        };
        let cur = send.capacity();
        if cur < buf.len() {
            send.reserve_capacity(buf.len() - cur);
        }
        let cap = match send.poll_capacity(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Some(Ok(cap))) => cap,
            Poll::Ready(Some(Err(e))) => {
                return Poll::Ready(Err(io::Error::other(format!("h2: capacity: {e}"))));
            }
            Poll::Ready(None) => {
                return Poll::Ready(Err(io::Error::other("h2: stream closed for writing")));
            }
        };
        if cap == 0 {
            return Poll::Pending;
        }
        let n = cap.min(buf.len());
        let chunk = Bytes::copy_from_slice(&buf[..n]);
        send.send_data(chunk, false)
            .map_err(|e| io::Error::other(format!("h2: send_data: {e}")))?;
        Poll::Ready(Ok(n))
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
