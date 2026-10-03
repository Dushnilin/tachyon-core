//! Kernel-side relay for plain TCP <-> TCP connections (Linux).
//!
//! `copy_bidirectional` and the tracked loop both move every byte through a
//! userspace buffer: a `read` into it, a `write` out of it, two copies across the
//! syscall boundary plus a pair of zeroed buffers per connection that stay
//! resident for as long as the connection lives. `splice(2)` moves the pages
//! between the two sockets inside the kernel instead, so the relay costs two
//! syscalls per chunk, no copy and no per-connection buffer.
//!
//! A direction takes its pipe only when the first byte shows up, so an idle
//! connection costs two sockets and nothing else. When a pipe cannot be had
//! (fd limit) that one direction drops to a small buffered loop instead of
//! failing the connection.

use std::io;
use std::os::fd::{AsRawFd, RawFd};

use tokio::io::Interest;
use tokio::net::TcpStream;

use crate::clash_state::ConnHandle;

/// Bytes asked from one splice. A pipe holds at most its capacity, so this is
/// also the size we grow the pipe to.
const CHUNK: usize = 256 * 1024;
/// Chunk of the buffered fallback, deliberately small: it only runs when fds
/// are scarce, and so is memory.
const FALLBACK_CHUNK: usize = 16 * 1024;

/// A non-blocking pipe pair that closes with its owner.
struct Pipe {
    read: RawFd,
    write: RawFd,
}

impl Pipe {
    fn new() -> io::Result<Self> {
        let mut fds = [0 as RawFd; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let pipe = Self {
            read: fds[0],
            write: fds[1],
        };
        // best effort: the default 64 KiB pipe works, it just needs more
        // round trips. Pages are only allocated while data is in flight.
        unsafe { libc::fcntl(pipe.write, libc::F_SETPIPE_SZ, CHUNK as libc::c_int) };
        Ok(pipe)
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.read);
            libc::close(self.write);
        }
    }
}

/// One `splice(2)` between two fds, one of which is a pipe. `EAGAIN` becomes
/// `WouldBlock`, which is what `async_io` waits on.
fn splice(from: RawFd, to: RawFd, len: usize) -> io::Result<usize> {
    let n = unsafe {
        libc::splice(
            from,
            std::ptr::null_mut(),
            to,
            std::ptr::null_mut(),
            len,
            libc::SPLICE_F_NONBLOCK | libc::SPLICE_F_MOVE,
        )
    };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

fn shutdown_write(stream: &TcpStream) {
    // the peer may already be gone; the half-close is a courtesy, not a duty
    let _ = socket2::SockRef::from(stream).shutdown(std::net::Shutdown::Write);
}

/// Write all of `data` to a non-blocking socket without needing `&mut`.
async fn write_all(stream: &TcpStream, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        let n = stream
            .async_io(Interest::WRITABLE, || stream.try_write(data))
            .await?;
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        data = &data[n..];
    }
    Ok(())
}

/// Move bytes `from` -> `to` until `from` reaches EOF, then half-close `to`.
async fn one_way(from: &TcpStream, to: &TcpStream, count: impl Fn(u64)) -> io::Result<()> {
    // an idle connection takes no pipe: wait for the first byte
    from.readable().await?;
    let Ok(pipe) = Pipe::new() else {
        return one_way_buffered(from, to, count).await;
    };
    let (from_fd, to_fd) = (from.as_raw_fd(), to.as_raw_fd());
    loop {
        let n = from
            .async_io(Interest::READABLE, || splice(from_fd, pipe.write, CHUNK))
            .await?;
        if n == 0 {
            shutdown_write(to);
            return Ok(());
        }
        // the pipe is empty before every refill, so `EAGAIN` above always
        // means "the socket has nothing" and below "the socket buffer is full"
        let mut left = n;
        while left > 0 {
            let m = to
                .async_io(Interest::WRITABLE, || splice(pipe.read, to_fd, left))
                .await?;
            if m == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            left -= m;
        }
        count(n as u64);
    }
}

/// The same direction through a small userspace buffer.
async fn one_way_buffered(from: &TcpStream, to: &TcpStream, count: impl Fn(u64)) -> io::Result<()> {
    let mut buf = vec![0u8; FALLBACK_CHUNK];
    loop {
        let n = from
            .async_io(Interest::READABLE, || from.try_read(&mut buf))
            .await?;
        if n == 0 {
            shutdown_write(to);
            return Ok(());
        }
        write_all(to, &buf[..n]).await?;
        count(n as u64);
    }
}

/// Relay both directions of an established connection until both sides are
/// done, counting into the Clash view as the userspace loop does and honouring
/// `DELETE /connections/{id}`. `prefix` is what the sniffer already read off the
/// client: it goes upstream first.
pub(crate) async fn relay(
    client: &TcpStream,
    upstream: &TcpStream,
    prefix: &[u8],
    tracker: &ConnHandle,
) -> io::Result<()> {
    if !prefix.is_empty() {
        write_all(upstream, prefix).await?;
        tracker.add_upload(prefix.len() as u64);
    }
    let signal = tracker.close_signal();
    let both = async {
        tokio::try_join!(
            one_way(client, upstream, |n| tracker.add_upload(n)),
            one_way(upstream, client, |n| tracker.add_download(n)),
        )
        .map(|_| ())
    };
    tokio::select! {
        result = both => result,
        _ = signal.wait() => Err(super::closed_by_api()),
    }
}
