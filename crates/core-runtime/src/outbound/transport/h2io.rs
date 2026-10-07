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

/// Receive window per stream and per connection. Sized to 1 MiB stream / 4 MiB
/// connection to sustain 10+ Gbps bulk transfers without ballooning client RSS
/// across concurrent streams.
const STREAM_WINDOW: u32 = 1 << 20;
const CONN_WINDOW: u32 = 4 << 20;
/// Largest DATA frame we ask the peer to send (the protocol default is 16 KiB;
/// Go's client asks for 1 MiB).
const MAX_FRAME: u32 = 256 << 10;

/// The client handshake every h2-based transport shares, with windows sized
/// for throughput.
pub(crate) fn client_builder() -> h2::client::Builder {
    let mut builder = h2::client::Builder::new();
    builder
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONN_WINDOW)
        .max_frame_size(MAX_FRAME);
    builder
}

/// The server half of the same handshake: same windows, so a server this side
/// runs is measured against the same conditions the client half asks for.
pub(crate) fn server_builder() -> h2::server::Builder {
    let mut builder = h2::server::Builder::new();
    builder
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONN_WINDOW)
        .max_frame_size(MAX_FRAME);
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
        let n = want - left;
        rdbg::bump(rdbg::SERVED, n as u64);
        n
    }

    /// Drop `n` pending bytes without copying them.
    pub(crate) fn skip_pending(&mut self, mut n: usize) {
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
        rdbg::init();
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
                Poll::Pending => {
                    rdbg::bump(rdbg::FLUSH_WAIT, 1);
                    return Poll::Pending;
                }
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
        rdbg::init();
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
            Poll::Pending => {
                rdbg::bump(rdbg::RECV_WAIT, 1);
                rdbg::note_recv_park();
                Poll::Pending
            }
            Poll::Ready(Some(Ok(chunk))) => {
                let len = chunk.len();
                let _ = recv.flow_control().release_capacity(len);
                // pushed as it arrived: no join, no copy of either side
                self.pending.push_back(chunk);
                self.pending_len += len;
                rdbg::bump(rdbg::RECV_MSG, 1);
                rdbg::note_recv_ready();
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
        loop {
            if !self.h2.pending.is_empty() {
                self.h2.serve(out, usize::MAX);
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
            // one alloc + one copy, and both are the AsyncWrite boundary
            // itself — see the note on `stage`
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

/// Temporary read/write path counters, on when `TACHYON_READDBG` is set: one
/// delta line per second appended to /tmp/tachyon-readbg.txt. Counts every
/// wait the pipeline can sit in -- a recv with nothing buffered, a capacity
/// that came back empty, an assembler with no record -- against the bytes
/// that actually moved, so a stall shows up as wait without served bytes.
pub(crate) mod rdbg {
    use std::sync::atomic::{AtomicU64, Ordering};

    pub const SERVED: usize = 0;
    pub const FLUSH_WAIT: usize = 1;
    pub const RECV_WAIT: usize = 2;
    pub const RECV_MSG: usize = 3;
    pub const A_READY: usize = 4;
    pub const A_PARK: usize = 5;
    pub const A_BYTES: usize = 6;
    pub const MSG: usize = 7;
    pub const CONN_POLL: usize = 8;
    pub const CYC_N: usize = 9;
    pub const CYC_SUM: usize = 10;
    pub const WAIT_SUM: usize = 11;
    pub const CONS_SUM: usize = 12;
    pub const HAND_SUM: usize = 13;
    pub const SRV_N: usize = 14;
    pub const SRV_SUM: usize = 15;
    pub const APP_N: usize = 16;
    pub const APP_SUM: usize = 17;
    pub const CD_N: usize = 18;
    pub const CD_SUM: usize = 19;
    pub const PK_N: usize = 20;
    pub const PK_E: usize = 21;
    pub const PK_SUM: usize = 22;
    pub const PK_MAX: usize = 23;
    pub const RD_SUM: usize = 24;
    pub const RD_MAX: usize = 25;

    const N: usize = 26;

    #[cfg(unix)]
    static FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);
    static T_CONN: AtomicU64 = AtomicU64::new(0);
    static T_READY: AtomicU64 = AtomicU64::new(0);
    static T_PARK: AtomicU64 = AtomicU64::new(0);

    pub(crate) fn now_ns() -> u64 {
        static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
        START
            .get_or_init(std::time::Instant::now)
            .elapsed()
            .as_nanos() as u64
    }

    /// One relay read call that came back with data: from entry to `Ready`,
    /// which is the grpc hunk handout plus the vmess decrypt that copies the
    /// payload onward. Split off `cons` so the residual -- the copy loop and
    /// the app socket write -- can be told apart from the protocol work.
    pub(crate) fn note_srv(t0: u64) {
        let t = now_ns();
        bump(SRV_N, 1);
        bump(SRV_SUM, t.saturating_sub(t0));
    }

    /// One write of relayed bytes into the client socket: how long the app
    /// side held the relay inside `poll_write` (a full receive window there
    /// is backpressure from the sink, not protocol cost).
    pub(crate) fn note_app(t0: u64) {
        let t = now_ns();
        bump(APP_N, 1);
        bump(APP_SUM, t.saturating_sub(t0));
    }

    pub(crate) fn note_conn_entry() {
        if C[CYC_N].load(Ordering::Relaxed) > 0 {
            T_CONN.store(now_ns(), Ordering::Relaxed);
        }
    }

    /// Last outbound TCP socket: the park probe below reads its unread depth,
    /// which tells a relay parked on nothing-buffers apart from one parked
    /// with bytes still sitting in the kernel.
    #[cfg(unix)]
    pub(crate) fn note_fd(fd: i32) {
        FD.store(fd, Ordering::Relaxed);
    }

    #[cfg(not(unix))]
    pub(crate) fn note_fd(_fd: i32) {}

    #[cfg(unix)]
    fn depth() -> i32 {
        let fd = FD.load(Ordering::Relaxed);
        if fd < 0 {
            return -1;
        }
        let mut n: libc::c_int = 0;
        // FIONREAD: bytes the kernel still holds for this socket
        let r = unsafe { libc::ioctl(fd, 0x541B, &mut n as *mut libc::c_int) };
        if r < 0 { -1 } else { n }
    }

    #[cfg(not(unix))]
    fn depth() -> i32 {
        -1
    }

    fn note_depth(dst_max: usize, dst_sum: usize) {
        let d = depth();
        if d >= 0 {
            bump(dst_sum, d as u64);
            C[dst_max].fetch_max(d as u64, Ordering::Relaxed);
        }
    }

    /// The relay saw a chunk: split the time since it last saw one into the
    /// part spent parked waiting for data and the part spent running.
    pub(crate) fn note_recv_ready() {
        let t = now_ns();
        let prev = T_READY.swap(t, Ordering::Relaxed);
        let park = T_PARK.load(Ordering::Relaxed);
        if prev == 0 || park < prev || t <= prev {
            return;
        }
        bump(CYC_N, 1);
        bump(CYC_SUM, t - prev);
        bump(WAIT_SUM, t - park);
        bump(CONS_SUM, park - prev);
        note_depth(RD_MAX, RD_SUM);
        let conn = T_CONN.load(Ordering::Relaxed);
        if conn < t {
            bump(HAND_SUM, t - conn);
        }
    }

    pub(crate) fn note_recv_park() {
        T_PARK.store(now_ns(), Ordering::Relaxed);
        bump(PK_N, 1);
        if depth() == 0 {
            bump(PK_E, 1);
        }
        note_depth(PK_MAX, PK_SUM);
    }

    /// Count polls of the h2 connection future: one per wake of the mux task.
    /// Against `recv_msg` this shows whether the connection parses one DATA
    /// chunk per wake (a ping-pong with the pump) or drains whole bursts.
    pub(crate) fn counted<F: std::future::Future>(
        f: F,
    ) -> impl std::future::Future<Output = F::Output> {
        struct Counted<F>(std::pin::Pin<Box<F>>);
        impl<F: std::future::Future> std::future::Future for Counted<F> {
            type Output = F::Output;
            fn poll(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<F::Output> {
                init();
                bump(CONN_POLL, 1);
                note_conn_entry();
                let t0 = now_ns();
                let poll = self.0.as_mut().poll(cx);
                bump(CD_N, 1);
                bump(CD_SUM, now_ns().saturating_sub(t0));
                poll
            }
        }
        Counted(Box::pin(f))
    }
    static C: [AtomicU64; N] = [const { AtomicU64::new(0) }; N];

    #[inline]
    pub(crate) fn bump(i: usize, n: u64) {
        C[i].fetch_add(n, Ordering::Relaxed);
    }

    fn snap() -> [u64; N] {
        std::array::from_fn(|i| C[i].load(Ordering::Relaxed))
    }

    pub(crate) fn init() {
        static ONCE: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| {
            if std::env::var_os("TACHYON_READDBG").is_none() {
                return;
            }
            std::thread::spawn(|| {
                let mut last = [0u64; N];
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    let cur = snap();
                    if cur == last {
                        continue;
                    }
                    use std::io::Write;
                    let Ok(mut f) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open("/tmp/tachyon-readbg.txt")
                    else {
                        continue;
                    };
                    let cyc_n = cur[CYC_N] - last[CYC_N];
                    let avg = |sum: u64| sum.checked_div(cyc_n).map_or(0, |v| v / 1000);
                    let own_avg = |sum: u64, n: u64| sum.checked_div(n.max(1)).map_or(0, |v| v / 1000);
                    let _ = writeln!(
                        f,
                        "{} served={} recv_msg={} recv_wait={} flush_wait={} msg={} a_ready={} a_park={} a_bytes={} conn_poll={} cyc={}us wait={}us cons={}us hand={}us srv={}us app={}us srv_n={} app_n={} cyc_n={} cd={}us cd_n={} pk_n={} pk_e={} pk_avg={} pk_max={} rd_avg={} rd_max={}",
                        std::process::id(),
                        cur[SERVED] - last[SERVED],
                        cur[RECV_MSG] - last[RECV_MSG],
                        cur[RECV_WAIT] - last[RECV_WAIT],
                        cur[FLUSH_WAIT] - last[FLUSH_WAIT],
                        cur[MSG] - last[MSG],
                        cur[A_READY] - last[A_READY],
                        cur[A_PARK] - last[A_PARK],
                        cur[A_BYTES] - last[A_BYTES],
                        cur[CONN_POLL] - last[CONN_POLL],
                        avg(cur[CYC_SUM] - last[CYC_SUM]),
                        avg(cur[WAIT_SUM] - last[WAIT_SUM]),
                        avg(cur[CONS_SUM] - last[CONS_SUM]),
                        avg(cur[HAND_SUM] - last[HAND_SUM]),
                        own_avg(cur[SRV_SUM] - last[SRV_SUM], cur[SRV_N] - last[SRV_N]),
                        own_avg(cur[APP_SUM] - last[APP_SUM], cur[APP_N] - last[APP_N]),
                        cur[SRV_N] - last[SRV_N],
                        cur[APP_N] - last[APP_N],
                        cyc_n,
                        own_avg(cur[CD_SUM] - last[CD_SUM], cur[CD_N] - last[CD_N]),
                        cur[CD_N] - last[CD_N],
                        cur[PK_N] - last[PK_N],
                        cur[PK_E] - last[PK_E],
                        own_avg(cur[PK_SUM] - last[PK_SUM], cur[PK_N] - last[PK_N]),
                        cur[PK_MAX],
                        (cur[RD_SUM] - last[RD_SUM])
                            .checked_div((cur[RECV_MSG] - last[RECV_MSG]).max(1))
                            .unwrap_or(0),
                        cur[RD_MAX],
                    );
                    last = cur;
                }
            });
        });
    }
}
