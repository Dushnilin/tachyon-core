//! `protect_path`: hand the socket's file descriptor to a helper over a unix
//! socket, which is how sing-box keeps its own traffic out of the VPN it is
//! serving. The reference does this in `control.ProtectPath`: send the
//! descriptor as an SCM_RIGHTS ancillary message, then read a one-byte answer.
//!
//! `sing/common/control/protect_other.go` makes it a no-op off unix, and the
//! path only means anything to a helper that implements the Android
//! `VpnService.protect` side -- but the wire protocol is ours to speak, and it is
//! testable without a phone.

use std::io::{self, Read as _};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;

/// Pass `fd` to the helper listening at `path` and wait for it to take the
/// descriptor. A one-byte reply is the acknowledgement; anything else means the
/// helper did not accept it.
pub fn protect(path: &str, fd: RawFd) -> io::Result<()> {
    let mut stream = UnixStream::connect(path)
        .map_err(|e| io::Error::other(format!("connect protect path {path}: {e}")))?;
    // A helper that hangs up before reading answers nothing, and the send says
    // so as EPIPE. Either way the descriptor was not accepted, and that is what
    // the caller has to hear.
    send_fd(&stream, fd).map_err(|e| io::Error::other(format!("failed to protect fd: {e}")))?;
    let mut ack = [0u8; 1];
    // No acknowledgement means the helper did not take the descriptor. Whether
    // that shows up as a reset, a broken pipe or a short read is the helper's
    // timing, not our problem to distinguish: the answer to the caller is the
    // same either way, and it is not a protected socket.
    match stream.read(&mut ack) {
        Ok(1) => Ok(()),
        Ok(read) => Err(io::Error::other(format!(
            "failed to protect fd: {read} of 1 bytes back"
        ))),
        Err(e) => Err(io::Error::other(format!("failed to protect fd: {e}"))),
    }
}

/// `CMSG_SPACE` for one descriptor. `CMSG_LEN` for the message itself, which is
/// a little shorter: the header sits between the two.
const fn cmsg_space() -> usize {
    // `CMSG_SPACE` is a compile-time constant in the C headers: the aligned size
    // of one `cmsghdr` plus `sizeof(c_int)`
    let align = std::mem::size_of::<usize>();
    let header = std::mem::size_of::<libc::cmsghdr>();
    header + std::mem::size_of::<RawFd>().next_multiple_of(align)
}

fn send_fd(stream: &UnixStream, fd: RawFd) -> io::Result<()> {
    let mut payload = [1u8];
    // the buffer and the header have to be in the same frame: a header holding
    // a pointer into a moved struct would dangle
    let mut buffer = vec![0 as libc::c_char; cmsg_space()];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    // SAFETY: zeroed memory is a valid message header once the fields below
    // describe buffers that outlive the call
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = buffer.as_mut_ptr().cast();
    // `msg_controllen` is `usize` on glibc and `u32` on musl, so the cast
    // target is the field's own type rather than either concrete width
    message.msg_controllen = buffer.len() as _;
    // SAFETY: the buffer is `CMSG_SPACE` bytes and the header points at it
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&message);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        std::ptr::copy_nonoverlapping(
            (&fd as *const RawFd).cast::<u8>(),
            libc::CMSG_DATA(cmsg),
            std::mem::size_of::<RawFd>(),
        );
    }
    // SAFETY: the header describes one control message inside the buffer and
    // one byte of payload
    let sent = unsafe { libc::sendmsg(stream.as_raw_fd(), &message, 0) };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The other half, for the helper: receive the one descriptor that came with
/// the message. This is what a `protect` helper implements.
pub fn recv_fd(stream: &UnixStream) -> io::Result<RawFd> {
    let mut payload = [0u8; 1];
    let mut buffer = vec![0 as libc::c_char; cmsg_space()];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    // SAFETY: as in `send_fd`, now the other direction
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = buffer.as_mut_ptr().cast();
    // `msg_controllen` is `usize` on glibc and `u32` on musl, so the cast
    // target is the field's own type rather than either concrete width
    message.msg_controllen = buffer.len() as _;
    // SAFETY: recvmsg fills the header, the payload and the control buffer
    let read = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, 0) };
    if read < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut fd: RawFd = -1;
    // SAFETY: a returned `SCM_RIGHTS` message holds one descriptor, which is
    // where the reference's own receive writes it
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&message);
        if cmsg.is_null() || (*cmsg).cmsg_type != libc::SCM_RIGHTS {
            return Err(io::Error::other("protect: no descriptor came with it"));
        }
        std::ptr::copy_nonoverlapping(
            libc::CMSG_DATA(cmsg),
            (&mut fd as *mut RawFd).cast::<u8>(),
            std::mem::size_of::<RawFd>(),
        );
    }
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::os::unix::net::UnixListener;

    use super::*;

    fn socket_path(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("tachyon-protect-{name}"));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let path = dir.join("protect.sock");
        let _ = std::fs::remove_file(&path);
        path
    }

    /// A helper that receives the descriptor and answers: that is the whole
    /// protocol, one message carrying the fd and one byte back.
    #[test]
    fn the_descriptor_arrives_and_the_ack_ends_it() {
        let path = socket_path("ok");
        let listener = UnixListener::bind(&path).expect("bind");
        let helper = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let fd = recv_fd(&stream).expect("descriptor");
            stream.write_all(&[1u8]).expect("ack");
            fd
        });
        let pair = UnixStream::pair().expect("pair");
        let mut client = pair.0.try_clone().expect("clone");
        protect(path.to_str().expect("path"), client.as_raw_fd()).expect("protect");
        let received = helper.join().expect("helper");
        assert!(received >= 0, "the descriptor did not survive the trip");
        // and it really is *our* descriptor: write through the other end and
        // read through the one we handed over
        let mut other = pair.1;
        other.write_all(&[7u8]).expect("write");
        let mut buf = [0u8; 1];
        client.read_exact(&mut buf).expect("read");
        assert_eq!(buf[0], 7, "the received descriptor was not ours");
        let _ = std::fs::remove_file(&path);
    }

    /// A helper that hangs up without answering is a failure, not a success:
    /// the reference reads the byte and checks the count.
    #[test]
    fn no_answer_is_not_a_protected_socket() {
        let path = socket_path("silent");
        let listener = UnixListener::bind(&path).expect("bind");
        let helper = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            drop(stream);
        });
        let pair = UnixStream::pair().expect("pair");
        let client = pair.0.try_clone().expect("clone");
        let err = protect(path.to_str().expect("path"), client.as_raw_fd())
            .expect_err("no ack, no protection");
        // the helper hung up, which reads as either a reset or a short read
        // depending on the kernel; both mean the descriptor was not accepted
        let message = err.to_string();
        assert!(message.contains("failed to protect fd"), "{err}");
        helper.join().expect("helper");
        let _ = std::fs::remove_file(&path);
    }

    /// And a path nobody is listening on is an error, not a panic.
    #[test]
    fn a_missing_helper_is_an_error() {
        let err =
            protect("/nonexistent/tachyon/protect.sock", 0).expect_err("nothing is listening");
        assert!(err.to_string().contains("connect protect path"), "{err}");
    }
}
