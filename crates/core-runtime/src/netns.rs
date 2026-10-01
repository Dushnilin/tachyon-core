//! Network namespaces (Linux only), which is what the `network_namespaces`
//! section and the `netns` dial field are for.
//!
//! The reference keeps this in `common/netns`: a tag map (`ResolvePath`), a
//! holder process per `unshare` namespace, and `ListenNetworkNamespace`, which
//! runs the caller's dial inside `runtime.LockOSThread` after a `setns`. That
//! detail is the whole reason this module spawns a thread of its own: `setns`
//! sticks to the thread, so doing it on a pooled one would hand the namespace to
//! whatever ran next.

use std::collections::HashMap;
use std::io;
use std::os::fd::AsRawFd;
use std::sync::{Mutex, OnceLock, RwLock};

/// tag -> `/proc/<pid>/ns/net` or the configured path.
fn tags() -> &'static RwLock<HashMap<String, String>> {
    static TAGS: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();
    TAGS.get_or_init(|| RwLock::new(HashMap::new()))
}

/// The holder processes, kept alive by holding their stdin open: when the pipe
/// closes, `hold` returns and the namespace goes with it.
fn holders() -> &'static Mutex<Vec<std::process::Child>> {
    static HOLDERS: OnceLock<Mutex<Vec<std::process::Child>>> = OnceLock::new();
    HOLDERS.get_or_init(|| Mutex::new(Vec::new()))
}

/// One entry of the `network_namespaces` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Attach to an existing namespace: `path` is a name or an absolute path.
    Default,
    /// Create one without privileges: a holder process keeps it open.
    Unshare,
}

#[derive(Debug, Clone)]
pub struct Namespace {
    pub kind: Kind,
    pub tag: String,
    pub path: String,
    pub pid_file: Option<String>,
}

/// A bare name is a namespace under `/run/netns`, as the reference resolves it.
fn default_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/run/netns/{path}")
    }
}

/// Read the section, check the `default` paths, and start the `unshare`
/// holders. Anything wrong here fails the start, as it does in the reference: a
/// namespace that cannot be entered is not something to discover on the first
/// dial. Returns the log lines the start should print.
pub fn setup(list: &[Namespace]) -> anyhow::Result<Vec<String>> {
    let mut map = HashMap::new();
    let mut log = Vec::new();
    for entry in list {
        if entry.tag.is_empty() {
            anyhow::bail!("network namespace: missing tag");
        }
        if map.contains_key(&entry.tag) {
            anyhow::bail!("network namespace: duplicated tag: {}", entry.tag);
        }
        let path = match entry.kind {
            Kind::Default => {
                if entry.path.is_empty() {
                    anyhow::bail!("network namespace[{}]: missing path", entry.tag);
                }
                let path = default_path(&entry.path);
                if !std::path::Path::new(&path).exists() {
                    anyhow::bail!("network namespace[{}]: {path}: no such file", entry.tag);
                }
                path
            }
            Kind::Unshare => {
                let (path, pid) = start_holder(entry.pid_file.as_deref())?;
                log.push(format!(
                    "network namespace[{}]: holder pid {pid}, enter with: nsenter -n -t {pid}",
                    entry.tag
                ));
                path
            }
        };
        map.insert(entry.tag.clone(), path);
    }
    *tags().write().expect("netns tags") = map;
    Ok(log)
}

/// A `netns` value is a tag first, then a name or a path, which is the order
/// the reference resolves it in.
pub fn resolve_path(name_or_tag: &str) -> String {
    match tags().read().expect("netns tags").get(name_or_tag) {
        Some(path) => path.clone(),
        None => default_path(name_or_tag),
    }
}

/// Run `block` inside the namespace, on a thread that belongs to nothing else.
///
/// The caller is expected to be on a blocking thread already; the namespace
/// switch happens on the thread spawned here, because `setns` is a per-thread
/// property and a pooled thread would carry it into the next task.
pub fn in_namespace<T, F>(name_or_tag: &str, block: F) -> io::Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> io::Result<T> + Send + 'static,
{
    let path = resolve_path(name_or_tag);
    std::thread::spawn(move || {
        let file = std::fs::File::open(&path)
            .map_err(|e| io::Error::other(format!("get netns {path}: {e}")))?;
        // SAFETY: `file` is an open namespace handle for the duration of the call
        if unsafe { libc::setns(file.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
            return Err(io::Error::last_os_error());
        }
        block()
    })
    .join()
    .unwrap_or_else(|payload| std::panic::resume_unwind(payload))
}

/// Start a process in a fresh network namespace and keep it alive. The path is
/// `/proc/<pid>/ns/net`, which is what `nsenter -n -t <pid>` wants.
fn start_holder(pid_file: Option<&str>) -> anyhow::Result<(String, u32)> {
    use std::os::unix::process::CommandExt as _;

    let exe = std::env::current_exe()?;
    let mut command = std::process::Command::new(exe);
    command
        .arg("netns-holder")
        .stdin(std::process::Stdio::piped());
    // SAFETY: unshare runs in the child between fork and exec, which is the only
    // place it can happen without a C helper
    unsafe {
        command.pre_exec(|| {
            if libc::unshare(libc::CLONE_NEWNET) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn()?;
    let pid = child.id();
    if let Some(path) = pid_file {
        if let Some(parent) = std::path::Path::new(path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(path, format!("{pid}\n"))?;
    }
    holders().lock().expect("netns holders").push(child);
    let path = format!("/proc/{pid}/ns/net");
    // the holder starts with loopback down and nothing else; the reference
    // brings `lo` up before anyone uses the namespace, and so do we
    in_namespace(&path, loopback_up)?;
    Ok((path, pid))
}

/// `ip link set lo up`, without `ip`: SIOCGIFFLAGS to read the flags, IFF_UP to
/// set them back.
fn loopback_up() -> io::Result<()> {
    let mut ifreq: libc::ifreq = unsafe { std::mem::zeroed() };
    for (slot, byte) in ifreq.ifr_name.iter_mut().zip(b"lo\0") {
        *slot = *byte as libc::c_char;
    }
    // SAFETY: `ifreq` is a live, correctly sized request for `lo`, and the
    // socket is only asked for its flags
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let get = libc::ioctl(fd, libc::SIOCGIFFLAGS as _, &mut ifreq);
        if get < 0 {
            return Err(io::Error::last_os_error());
        }
        ifreq.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
        let set = libc::ioctl(fd, libc::SIOCSIFFLAGS as _, &ifreq);
        libc::close(fd);
        if set < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// What the holder subcommand does: nothing, until stdin closes.
pub fn hold() {
    use std::io::Read as _;

    let mut buffer = [0u8; 1];
    loop {
        match std::io::stdin().read(&mut buffer) {
            Ok(0) | Err(_) => std::process::exit(0),
            Ok(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_name_is_under_run_netns() {
        assert_eq!(default_path("sing"), "/run/netns/sing");
        assert_eq!(default_path("/proc/1/ns/net"), "/proc/1/ns/net");
    }

    #[test]
    fn a_tag_wins_over_a_name() {
        let mut map = HashMap::new();
        map.insert("vpn".to_string(), "/proc/42/ns/net".to_string());
        *tags().write().expect("tags") = map;
        assert_eq!(resolve_path("vpn"), "/proc/42/ns/net");
        assert_eq!(resolve_path("other"), "/run/netns/other");
        *tags().write().expect("tags") = HashMap::new();
    }

    #[test]
    fn a_missing_tag_or_path_fails_the_setup() {
        let err = setup(&[Namespace {
            kind: Kind::Default,
            tag: String::new(),
            path: "sing".into(),
            pid_file: None,
        }])
        .expect_err("no tag");
        assert!(err.to_string().contains("missing tag"), "{err}");
        let err = setup(&[Namespace {
            kind: Kind::Default,
            tag: "vpn".into(),
            path: String::new(),
            pid_file: None,
        }])
        .expect_err("no path");
        assert!(err.to_string().contains("missing path"), "{err}");
        let err = setup(&[Namespace {
            kind: Kind::Default,
            tag: "vpn".into(),
            path: "/run/netns/definitely-not-here".into(),
            pid_file: None,
        }])
        .expect_err("no such namespace");
        assert!(err.to_string().contains("no such file"), "{err}");
    }

    #[test]
    fn duplicated_tags_are_refused() {
        let err = setup(&[
            Namespace {
                kind: Kind::Default,
                tag: "vpn".into(),
                path: "/proc/self/ns/net".into(),
                pid_file: None,
            },
            Namespace {
                kind: Kind::Default,
                tag: "vpn".into(),
                path: "/proc/self/ns/net".into(),
                pid_file: None,
            },
        ])
        .expect_err("twice");
        assert!(err.to_string().contains("duplicated"), "{err}");
    }

    /// Entering our own namespace is the setns path without needing a second
    /// namespace or a privilege we may not have.
    #[test]
    fn entering_the_current_namespace_works() {
        match in_namespace("/proc/self/ns/net", || {
            std::fs::read_link("/proc/self/ns/net").map(|link| link.display().to_string())
        }) {
            Ok(link) => assert!(link.starts_with("net:["), "{link}"),
            // setns needs CAP_SYS_ADMIN even for your own namespace
            Err(e) if e.raw_os_error() == Some(libc::EPERM) => {
                eprintln!("setns is not permitted here: {e}");
            }
            Err(e) => panic!("setns failed: {e}"),
        }
    }

    /// A `default` namespace that does not exist fails the start, the way it
    /// fails the reference's `Manager.Start`.
    #[test]
    fn a_default_namespace_that_is_not_there_stops_the_start() {
        let err = setup(&[Namespace {
            kind: Kind::Default,
            tag: "vpn".into(),
            path: "/run/netns/definitely-not-here".into(),
            pid_file: None,
        }])
        .expect_err("no such namespace");
        assert!(err.to_string().contains("no such file"), "{err}");
    }

    /// And the section the reference builds, read the way `start()` reads it.
    #[test]
    fn the_section_is_read_the_way_the_reference_reads_it() {
        let list: serde_json::Value = serde_json::from_str(
            r#"[
                {"type": "default", "tag": "vpn", "path": "/proc/self/ns/net"},
                {"type": "unshare", "tag": "fresh", "pid_file": "/tmp/tachyon-netns.pid"}
            ]"#,
        )
        .expect("json");
        let mut tags = std::collections::HashMap::new();
        for (index, entry) in list.as_array().expect("list").iter().enumerate() {
            let kind = match entry.get("type").and_then(|v| v.as_str()).unwrap_or("") {
                "" | "default" => Kind::Default,
                "unshare" => Kind::Unshare,
                other => panic!("unknown type: {other}"),
            };
            let tag = entry
                .get("tag")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            assert!(!tag.is_empty(), "entry {index} has no tag");
            tags.insert(tag, kind);
        }
        assert_eq!(tags.get("vpn"), Some(&Kind::Default));
        assert_eq!(tags.get("fresh"), Some(&Kind::Unshare));
    }

    /// And a block that fails inside the namespace still fails out here.
    /// Where `setns` itself is refused the block never runs, which is the same
    /// answer with a different reason, so both count.
    #[test]
    fn a_failure_inside_comes_back_out() {
        let result: io::Result<()> =
            in_namespace("/proc/self/ns/net", || Err(io::Error::other("from inside")));
        match result {
            Ok(()) => panic!("the block should have failed"),
            Err(e) => assert!(
                e.to_string() == "from inside" || e.raw_os_error() == Some(libc::EPERM),
                "{e}"
            ),
        }
    }
}
