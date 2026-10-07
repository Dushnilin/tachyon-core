//! `route.find_process`: which process opened this connection.
//!
//! The reference asks its platform for the owner of a socket and matches the
//! result against the `process_name` / `process_path` / `process_path_regex` /
//! `user` / `user_id` rule items (reference `route/process_cache.go`,
//! `route/rule/rule_item_process_*`).
//!
//! On Linux the owner is found the way every `ss -p`-alike does it: the socket's
//! inode comes from `/proc/net/{tcp,tcp6,udp,udp6}`, and the process holding it
//! is the one with an `fd` symlinked to `socket:[inode]`. The path is
//! `/proc/<pid>/exe`, the uid the `Uid:` line of `/proc/<pid>/status`, and the
//! user name that uid maps to in `/etc/passwd`.
//!
//! On other platforms the searcher is the reference's stub, which reports "not
//! found" — the rule items then never match, exactly as they do there.

use std::net::IpAddr;
use std::net::SocketAddr;

/// The owner of a socket, as the reference's `adapter.ConnectionOwner`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    /// `/proc/<pid>/exe`; empty when the process is gone or unreadable.
    pub path: String,
    /// Real uid, or `None` when the process is gone.
    pub user_id: Option<u32>,
    /// The name that uid maps to in `/etc/passwd`, if any.
    pub user_name: Option<String>,
}

impl ProcessInfo {
    /// `process_name` matches the last element of the path, not `comm`
    /// (reference `ProcessItem.Match`: `filepath.Base(ProcessPath)`).
    pub fn name(&self) -> &str {
        match self.path.rsplit_once('/') {
            Some((_, name)) => name,
            None => &self.path,
        }
    }
}

/// The owner of the socket this connection runs on, or `None`. The caller
/// decides whether to look at all: without `route.find_process` and without a
/// rule that needs it, the `/proc` walk is skipped, like the reference's
/// `needFindProcess`.
pub fn find_owner(
    network: &str,
    source: SocketAddr,
    destination: Option<SocketAddr>,
) -> Option<ProcessInfo> {
    // `searchProcessInfo` only looks at local sources: a remote client's
    // process is not something this machine can see
    if !source.ip().is_loopback() && !is_private(source.ip()) {
        return None;
    }
    #[cfg(target_os = "linux")]
    {
        linux::find_owner(network, source, destination)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (network, source, destination);
        None
    }
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local() || v4.is_unspecified(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00 || v6.is_unspecified()
        }
    }
}

/// `0100007F:1F90` for 127.0.0.1:8080, the shape `/proc/net/*` prints: the
/// address as 32-bit words in host order, the port as one word. Only the Linux
/// searcher reads it; elsewhere the test below is the only caller.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn addr_hex(ip: IpAddr, port: u16) -> String {
    let octets = match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };
    let mut out = String::new();
    for word in octets.chunks(4) {
        out.push_str(&format!(
            "{:08X}",
            u32::from_ne_bytes(word.try_into().expect("4 bytes"))
        ));
    }
    out.push(':');
    out.push_str(&format!("{port:04X}"));
    out
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    /// The `/proc/net` files per network, and whether a remote endpoint has to
    /// match: a connected TCP socket has one, a UDP socket that never sent
    /// anything does not.
    fn tables(network: &str) -> (&'static [&'static str], bool) {
        match network {
            "tcp" => (&["/proc/net/tcp", "/proc/net/tcp6"], true),
            "udp" => (&["/proc/net/udp", "/proc/net/udp6"], false),
            _ => (&[], true),
        }
    }

    pub(super) fn find_owner(
        network: &str,
        source: SocketAddr,
        destination: Option<SocketAddr>,
    ) -> Option<ProcessInfo> {
        let (files, need_remote) = tables(network);
        let inode = socket_inode(files, source, destination, need_remote)?;
        process_for_inode(inode)
    }

    #[derive(PartialEq, Eq, Hash, Clone, Copy)]
    enum Key {
        Inode(u64),
        Pid(u32),
    }

    /// A few seconds of `inode → owner` and `pid → owner`, like the
    /// reference's `route/process_cache.go`: the fd walk and the
    /// `/proc/<pid>` reads per connection are the expensive halves, and a
    /// pid is reused by every connection its process opens.
    fn process_for_inode(inode: u64) -> Option<ProcessInfo> {
        use std::collections::HashMap;
        use std::sync::{Mutex, OnceLock};
        use std::time::{Duration, Instant};

        const TTL: Duration = Duration::from_secs(3);
        static CACHE: OnceLock<Mutex<HashMap<Key, (Instant, ProcessInfo)>>> = OnceLock::new();

        fn fresh(
            cache: &Mutex<HashMap<Key, (Instant, ProcessInfo)>>,
            key: Key,
        ) -> Option<ProcessInfo> {
            let map = cache.lock().expect("process cache");
            let (at, info) = map.get(&key)?;
            (at.elapsed() < TTL).then(|| info.clone())
        }

        let cache = CACHE.get_or_init(Mutex::default);
        if let Some(info) = fresh(cache, Key::Inode(inode)) {
            return Some(info);
        }
        let pid = pid_for_inode(inode)?;
        let info = match fresh(cache, Key::Pid(pid)) {
            Some(info) => info,
            None => {
                let info = read_process(pid)?;
                cache
                    .lock()
                    .expect("process cache")
                    .insert(Key::Pid(pid), (Instant::now(), info.clone()));
                info
            }
        };
        cache
            .lock()
            .expect("process cache")
            .insert(Key::Inode(inode), (Instant::now(), info.clone()));
        Some(info)
    }

    /// The inode of the socket with this local endpoint, from one table.
    /// A row is `sl local_address rem_address st tx:rx tr:tm->when retrnsmt uid
    /// timeout inode …`, with `sl` printed as `N:`, so the inode is the tenth
    /// field and the addresses the second and third.
    pub(super) fn inode_in_table(text: &str, local: &str, remote: Option<&str>) -> Option<u64> {
        for line in text.lines().skip(1) {
            let mut fields = line.split_whitespace();
            fields.next()?; // `N:`
            if fields.next()? != local {
                continue;
            }
            // consumed either way: the columns after it shift without it
            let row_remote = fields.next()?;
            if let Some(want) = remote
                && row_remote != want
            {
                continue;
            }
            // tx:rx, tr:tm->when, retrnsmt, uid, timeout, then the inode
            if let Some(inode) = fields.nth(6).and_then(|f| f.parse::<u64>().ok())
                && inode != 0
            {
                return Some(inode);
            }
        }
        None
    }

    fn socket_inode(
        files: &[&str],
        local: SocketAddr,
        remote: Option<SocketAddr>,
        need_remote: bool,
    ) -> Option<u64> {
        let local_hex = addr_hex(local.ip(), local.port());
        let remote_hex = remote
            .filter(|_| need_remote)
            .map(|remote| addr_hex(remote.ip(), remote.port()));
        for file in files {
            let Ok(text) = std::fs::read_to_string(file) else {
                continue;
            };
            if let Some(inode) = inode_in_table(&text, &local_hex, remote_hex.as_deref()) {
                return Some(inode);
            }
        }
        None
    }

    /// The first process with an open `fd` pointing at `socket:[inode]`.
    fn pid_for_inode(inode: u64) -> Option<u32> {
        let want = format!("socket:[{inode}]");
        for entry in std::fs::read_dir("/proc").ok()? {
            let Ok(entry) = entry else { continue };
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if !name.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            for fd in std::fs::read_dir(entry.path().join("fd"))
                .into_iter()
                .flatten()
                .flatten()
            {
                let target = std::fs::read_link(fd.path());
                if target.is_ok_and(|target| target.to_string_lossy() == want) {
                    return name.parse().ok();
                }
            }
        }
        None
    }

    fn read_process(pid: u32) -> Option<ProcessInfo> {
        let dir = std::path::PathBuf::from(format!("/proc/{pid}"));
        let user_id = read_uid(&dir);
        let path = std::fs::read_link(dir.join("exe"))
            .ok()
            .map(|path| path.to_string_lossy().into_owned())
            .filter(|path| !path.is_empty())
            .or_else(|| cmdline_path(&dir))?;
        Some(ProcessInfo {
            path,
            user_id,
            user_name: user_id.and_then(user_name),
        })
    }

    /// The real uid: the first field of the `Uid:` line.
    fn read_uid(dir: &std::path::Path) -> Option<u32> {
        let status = std::fs::read_to_string(dir.join("status")).ok()?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("Uid:") {
                return rest.split_whitespace().next()?.parse().ok();
            }
        }
        None
    }

    /// A process whose `exe` we may not read still has a `cmdline`, and an
    /// absolute argv[0] is the same path.
    fn cmdline_path(dir: &std::path::Path) -> Option<String> {
        let raw = std::fs::read(dir.join("cmdline")).ok()?;
        let first = raw.split(|byte| *byte == 0).next()?;
        let text = std::str::from_utf8(first).ok()?;
        (!text.is_empty() && text.starts_with('/')).then(|| text.to_string())
    }

    /// The name of a uid, from `/etc/passwd` — the reference's `UserName`.
    fn user_name(uid: u32) -> Option<String> {
        let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
        for line in passwd.lines() {
            let mut fields = line.split(':');
            let name = fields.next()?;
            let _password = fields.next()?;
            let entry_uid: u32 = fields.next()?.parse().ok()?;
            if entry_uid == uid {
                return Some(name.to_string());
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_name_is_the_last_path_element() {
        let info = ProcessInfo {
            path: "/usr/bin/sing-box".to_string(),
            user_id: Some(0),
            user_name: Some("root".to_string()),
        };
        assert_eq!(info.name(), "sing-box");
        assert_eq!(
            ProcessInfo {
                path: String::new(),
                user_id: None,
                user_name: None
            }
            .name(),
            ""
        );
    }

    /// Rows captured from a live container (`/proc/net/tcp`), so the column
    /// layout is checked where it is actually parsed instead of only on a
    /// machine that happens to have a socket to look up.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_inode_comes_out_of_a_real_proc_net_row() {
        let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:A139 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 477963 1 0000000097aff9c4 100 0 0 10 0\n\
   1: 0100007F:AD7A 0100007F:A139 01 00000000:00000000 00:00000000 00000000     0        0 477964 2 0000000023aa6b4e 20 0 0 10 -1\n\
   2: 0100007F:A139 0100007F:AD7A 01 00000000:00000000 00:00000000 00000000     0        0 477965 1 000000006e3ee3bf 20 0 0 10 -1\n";
        let local = addr_hex("127.0.0.1".parse().unwrap(), 44410);
        let remote = addr_hex("127.0.0.1".parse().unwrap(), 41273);
        assert_eq!(
            linux::inode_in_table(table, &local, Some(&remote)),
            Some(477964),
            "the established socket, matched on both endpoints"
        );
        assert_eq!(
            linux::inode_in_table(table, &local, None),
            Some(477964),
            "a listening lookup without a remote still finds the row"
        );
        assert_eq!(
            linux::inode_in_table(table, &addr_hex("127.0.0.1".parse().unwrap(), 1), None),
            None,
            "a port with no row matches nothing"
        );
    }

    #[test]
    fn proc_addresses_print_as_the_kernel_does() {
        // /proc/net/tcp prints 127.0.0.1:8080 as 0100007F:1F90
        assert_eq!(
            addr_hex("127.0.0.1".parse().unwrap(), 8080),
            "0100007F:1F90"
        );
        assert_eq!(
            addr_hex("::1".parse().unwrap(), 53),
            "00000000000000000000000001000000:0035"
        );
    }

    #[test]
    fn only_local_sources_are_searched() {
        assert!(
            find_owner("tcp", "8.8.8.8:5000".parse().unwrap(), None).is_none(),
            "a remote client's process is not ours to look up"
        );
        assert!(
            find_owner("icmp", "127.0.0.1:5000".parse().unwrap(), None).is_none(),
            "only tcp and udp have a socket to look up"
        );
    }

    /// The owner of a socket this test itself opened, on Linux.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_owner_of_a_socket_is_the_process_holding_it() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let client = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        let source = client.local_addr().expect("source");

        // the socket is the client's: local = the client, remote = the server
        let owner = find_owner("tcp", source, Some(server.local_addr().expect("server")))
            .expect("the test process holds that socket");
        let own_exe = std::fs::read_link("/proc/self/exe").expect("own exe");
        assert_eq!(
            owner.path.trim_end_matches(" (deleted)"),
            own_exe.to_string_lossy()
        );
        let own_uid: u32 = std::fs::read_to_string("/proc/self/status")
            .expect("status")
            .lines()
            .find_map(|line| {
                line.strip_prefix("Uid:")?
                    .split_whitespace()
                    .next()?
                    .parse()
                    .ok()
            })
            .expect("uid");
        assert_eq!(owner.user_id, Some(own_uid));
        drop((client, server));
    }
}
