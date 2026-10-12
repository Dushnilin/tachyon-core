use core_runtime::cache_file::{CacheFile, CacheFileOptions};
use core_runtime::dns::transport::{FakeIpStore, IpPrefix};
use core_runtime::inbound::Target;
use core_runtime::route::ConnContext;
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

fn pool() -> FakeIpStore {
    FakeIpStore::new(
        Some(IpPrefix::parse("198.18.0.0/15").unwrap()),
        Some(IpPrefix::parse("fc00::/18").unwrap()),
    )
}

#[test]
fn fakeip_survives_reopen_and_preserves_binary_keys_and_cursors() {
    let path = std::env::temp_dir().join(format!("tachyon-fakeip-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let options = CacheFileOptions {
        enabled: true,
        store_fakeip: true,
        path: path.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let cache = Arc::new(Mutex::new(
        CacheFile::open(options.clone()).unwrap().unwrap(),
    ));
    let first = pool();
    first.attach_cache(Some(cache.clone()));
    let v4 = first.create("first.example", false).unwrap();
    let v6 = first.create("first.example", true).unwrap();
    // Distinct invalid UTF-8 binary keys used to collapse to the same lossy string.
    cache.lock().unwrap().put("foreign", &[0xfe], vec![1]);
    cache.lock().unwrap().put("foreign", &[0xff], vec![2]);
    cache.lock().unwrap().flush().unwrap();
    drop((first, cache));
    let cache = Arc::new(Mutex::new(
        CacheFile::open(options.clone()).unwrap().unwrap(),
    ));
    let reopened = pool();
    reopened.attach_cache(Some(cache.clone()));
    for (ip, v6) in [(v4, false), (v6, true)] {
        assert_eq!(reopened.lookup_domain(ip).as_deref(), Some("first.example"));
        assert_eq!(reopened.create("first.example", v6).unwrap(), ip);
        assert_ne!(reopened.create("second.example", v6).unwrap(), ip);
    }
    assert_eq!(cache.lock().unwrap().get("foreign", &[0xfe]), Some(vec![1]));
    assert_eq!(cache.lock().unwrap().get("foreign", &[0xff]), Some(vec![2]));
    // A Go-formatted cache has packed address keys and raw address values.
    let go_ip = Ipv4Addr::new(198, 18, 1, 200);
    cache
        .lock()
        .unwrap()
        .put("fakeip_address", &go_ip.octets(), b"go.example".to_vec());
    cache
        .lock()
        .unwrap()
        .put("fakeip_domain4", b"go.example", go_ip.octets().to_vec());
    cache
        .lock()
        .unwrap()
        .delete("fakeip_address", b"fakeip_metadata");
    cache.lock().unwrap().flush().unwrap();
    drop((reopened, cache));
    let cache = Arc::new(Mutex::new(CacheFile::open(options).unwrap().unwrap()));
    let imported = pool();
    imported.attach_cache(Some(cache.clone()));
    assert_eq!(
        imported.lookup_domain(go_ip.into()).as_deref(),
        Some("go.example")
    );
    assert_eq!(
        imported.create("go.example", false).unwrap(),
        IpAddr::V4(go_ip)
    );
    // A fresh import resumes beyond the highest Go address.
    let next = imported.create("after-import.example", false).unwrap();
    assert_eq!(next, IpAddr::V4(Ipv4Addr::new(198, 18, 1, 201)));
    let disabled = pool();
    cache.lock().unwrap().flush().unwrap();
    let disabled_cache = Arc::new(Mutex::new(
        CacheFile::open(CacheFileOptions {
            enabled: true,
            path: path.to_string_lossy().into_owned(),
            ..Default::default()
        })
        .unwrap()
        .unwrap(),
    ));
    disabled.attach_cache(Some(disabled_cache));
    assert_eq!(disabled.lookup_domain(go_ip.into()), None);
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn runtime_rejects_unknown_fakeip_and_flushes_on_shutdown() {
    let path =
        std::env::temp_dir().join(format!("tachyon-fakeip-runtime-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let root = json!({"outbounds":[{"type":"direct","tag":"direct"}],
        "route":{"final":"direct"},
        "dns":{"servers":[{"type":"fakeip","tag":"fake","inet4_range":"198.18.0.0/15","inet6_range":"fc00::/18"},
            {"type":"hosts","tag":"hosts","path":[],"predefined":{}}],"final":"hosts"},
        "experimental":{"cache_file":{"enabled":true,"store_fakeip":true,"flush_interval":"1s","path":path}}});
    let mut instance = core_runtime::start(&root).await.unwrap();
    let dns = core_runtime::dns::current().unwrap();
    let store = dns.fakeip_stores().pop().unwrap();
    let allocated = store.create("saved.example", false).unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    let on_disk = CacheFile::open(CacheFileOptions {
        enabled: true,
        path: path.to_string_lossy().into_owned(),
        ..Default::default()
    })
    .unwrap()
    .unwrap();
    let IpAddr::V4(address) = allocated else {
        panic!("IPv4 allocation")
    };
    assert_eq!(
        on_disk.get("fakeip_address", &address.octets()).as_deref(),
        Some(b"saved.example".as_slice())
    );
    for network in ["tcp", "udp"] {
        for ip in ["198.18.1.50", "fc00::123"] {
            let mut ctx = ConnContext::new(
                "test",
                "127.0.0.1:12345".parse().unwrap(),
                Target::Ip(
                    format!(
                        "{}:443",
                        if ip.contains(':') {
                            format!("[{ip}]")
                        } else {
                            ip.into()
                        }
                    )
                    .parse()
                    .unwrap(),
                ),
                network,
            );
            let error = instance.router().route_raw(&mut ctx).await.unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
            assert_eq!(error.to_string(), "missing fakeip record");
        }
    }
    instance.shutdown_wait().await;
    let mut instance = core_runtime::start(&root).await.unwrap();
    assert_eq!(
        core_runtime::dns::current()
            .unwrap()
            .fakeip_domain(allocated)
            .as_deref(),
        Some("saved.example")
    );
    instance.shutdown_wait().await;
    std::fs::remove_file(path).unwrap();
}

#[test]
fn go_metadata_cursor_and_wrap_preserve_paired_records() {
    let path =
        std::env::temp_dir().join(format!("tachyon-fakeip-go-meta-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let options = CacheFileOptions {
        enabled: true,
        store_fakeip: true,
        path: path.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let cache = Arc::new(Mutex::new(
        CacheFile::open(options.clone()).unwrap().unwrap(),
    ));
    // Go adapter.FakeIPMetadata: uint16 BE lengths followed by netip
    // prefix/address binary encodings. IPv6 is an invalid/absent prefix.
    let metadata = vec![
        0, 5, 198, 18, 0, 0, 15, 0, 1, 255, 0, 4, 198, 18, 0, 200, 0, 0,
    ];
    cache
        .lock()
        .unwrap()
        .put("fakeip_address", b"fakeip_metadata", metadata);
    let imported = FakeIpStore::new(Some(IpPrefix::parse("198.18.0.0/15").unwrap()), None);
    imported.attach_cache(Some(cache.clone()));
    assert_eq!(
        imported.create("next.example", false).unwrap(),
        "198.18.0.201".parse::<IpAddr>().unwrap()
    );
    let small = FakeIpStore::new(Some(IpPrefix::parse("198.18.0.0/30").unwrap()), None);
    small.attach_cache(Some(cache.clone()));
    let old = small.create("old.example", false).unwrap();
    let new = small.create("new.example", false).unwrap();
    assert_eq!(old, new);
    assert_eq!(small.lookup_address("old.example", false), None);
    assert_eq!(small.lookup_domain(new).as_deref(), Some("new.example"));
    cache.lock().unwrap().flush().unwrap();
    drop((small, imported, cache));
    let cache = Arc::new(Mutex::new(CacheFile::open(options).unwrap().unwrap()));
    let reopened = FakeIpStore::new(Some(IpPrefix::parse("198.18.0.0/30").unwrap()), None);
    reopened.attach_cache(Some(cache));
    assert_eq!(reopened.lookup_domain(new).as_deref(), Some("new.example"));
    assert_eq!(reopened.lookup_address("old.example", false), None);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn lru_eviction_removes_both_reverse_maps_without_persistent_cache() {
    let store = pool();
    let first4 = store.create("first.example", false).unwrap();
    let first6 = store.create("first.example", true).unwrap();
    for index in 0..16384 {
        let domain = format!("eviction-{index}.example");
        store.create(&domain, false).unwrap();
        store.create(&domain, true).unwrap();
    }
    assert_eq!(store.lookup_address("first.example", false), None);
    assert_eq!(store.lookup_address("first.example", true), None);
    assert_eq!(store.lookup_domain(first4), None);
    assert_eq!(store.lookup_domain(first6), None);
    let last = "eviction-16383.example";
    let address = store.lookup_address(last, false).unwrap();
    assert_eq!(store.lookup_domain(address).as_deref(), Some(last));
}

fn octets(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}

fn test_cache(options: &CacheFileOptions) -> Arc<Mutex<CacheFile>> {
    Arc::new(Mutex::new(
        CacheFile::open(options.clone()).unwrap().unwrap(),
    ))
}

fn temp_options(tag: &str) -> CacheFileOptions {
    let path = std::env::temp_dir().join(format!("tachyon-fakeip-{tag}-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    CacheFileOptions {
        enabled: true,
        store_fakeip: true,
        path: path.to_string_lossy().into_owned(),
        ..Default::default()
    }
}

/// Issue #135: a forward record on disk whose reverse record was lost lets
/// `create` answer from disk while `lookup_domain` — the reverse half of the
/// TPROXY path — finds nothing, and the connection dies as
/// "missing fakeip record".
#[test]
fn disk_only_forward_record_carries_the_whole_pair() {
    let options = temp_options("fwd-only");
    let cache = test_cache(&options);
    let ip = "198.18.0.7".parse::<IpAddr>().unwrap();
    cache
        .lock()
        .unwrap()
        .put("fakeip_domain4", b"github.com", octets(ip));

    let store = FakeIpStore::new(Some(IpPrefix::parse("198.18.0.0/15").unwrap()), None);
    store.attach_cache(Some(cache.clone()));
    assert_eq!(store.create("github.com", false).unwrap(), ip);
    assert_eq!(store.lookup_domain(ip).as_deref(), Some("github.com"));

    let _ = std::fs::remove_file(&options.path);
}

/// A record that lands on disk after attach (a foreign writer, a late flush)
/// must take the same hydrate-and-heal path in `create`.
#[test]
fn create_disk_hit_rehydrates_memory_and_heals_the_reverse_record() {
    let options = temp_options("create-hydrate");
    let cache = test_cache(&options);
    let store = FakeIpStore::new(Some(IpPrefix::parse("198.18.0.0/15").unwrap()), None);
    store.attach_cache(Some(cache.clone()));

    let ip = "198.18.0.9".parse::<IpAddr>().unwrap();
    let IpAddr::V4(addr) = ip else {
        panic!("IPv4 allocation")
    };
    cache
        .lock()
        .unwrap()
        .put("fakeip_domain4", b"late.example", addr.octets().to_vec());

    assert_eq!(store.create("late.example", false).unwrap(), ip);
    // in-memory reverse works immediately…
    assert_eq!(store.lookup_domain(ip).as_deref(), Some("late.example"));
    // …and persist healed the missing reverse record on disk
    cache.lock().unwrap().flush().unwrap();
    assert_eq!(
        cache
            .lock()
            .unwrap()
            .get("fakeip_address", &addr.octets())
            .as_deref(),
        Some(b"late.example".as_slice())
    );
    drop(store);
    drop(cache);

    std::fs::remove_file(&options.path).unwrap();
}

/// A disk hit on the reverse path is mirrored into memory, so the next lookup
/// no longer depends on the record still being readable.
#[test]
fn lookup_domain_caches_disk_hits_in_memory() {
    let options = temp_options("rev-cache");
    let cache = test_cache(&options);
    let store = FakeIpStore::new(Some(IpPrefix::parse("198.18.0.0/15").unwrap()), None);
    store.attach_cache(Some(cache.clone()));

    let ip = "198.18.0.11".parse::<IpAddr>().unwrap();
    cache
        .lock()
        .unwrap()
        .put("fakeip_address", &octets(ip), b"cached.example".to_vec());
    assert_eq!(store.lookup_domain(ip).as_deref(), Some("cached.example"));

    cache.lock().unwrap().delete("fakeip_address", &octets(ip));
    assert_eq!(store.lookup_domain(ip).as_deref(), Some("cached.example"));

    let _ = std::fs::remove_file(&options.path);
}

#[test]
fn eviction_removes_both_forward_and_reverse_from_persistent_cache_atomically() {
    let mut options = temp_options("evict-atomic");
    options.flush_interval = std::time::Duration::from_secs(60);
    let cache = test_cache(&options);
    let store = FakeIpStore::new(Some(IpPrefix::parse("198.18.0.0/15").unwrap()), None);
    store.attach_cache(Some(cache.clone()));

    let first_ip = store.create("first.example", false).unwrap();
    cache.lock().unwrap().flush().unwrap();
    assert!(
        cache
            .lock()
            .unwrap()
            .get("fakeip_domain4", b"first.example")
            .is_some()
    );
    assert_eq!(
        cache
            .lock()
            .unwrap()
            .get("fakeip_address", &octets(first_ip))
            .as_deref(),
        Some(b"first.example".as_slice())
    );

    // Evict `first.example` by filling LRU capacity (16384):
    for i in 0..16384 {
        let domain = format!("item-{i}.example");
        store.create(&domain, false).unwrap();
    }
    cache.lock().unwrap().flush().unwrap();

    // Verify both forward and reverse records are deleted atomically from persistent cache:
    assert_eq!(
        cache
            .lock()
            .unwrap()
            .get("fakeip_domain4", b"first.example"),
        None,
        "forward record must be deleted on LRU eviction"
    );
    assert_eq!(
        cache
            .lock()
            .unwrap()
            .get("fakeip_address", &octets(first_ip)),
        None,
        "reverse record must be deleted on LRU eviction"
    );

    let _ = std::fs::remove_file(&options.path);
}

#[test]
fn memory_and_disk_hits_do_not_dirty_the_cache_or_write_to_flash() {
    let options = temp_options("flash-protect");
    let cache = test_cache(&options);
    let store = pool();
    store.attach_cache(Some(cache.clone()));

    // Create a domain:
    let ip = store.create("saved.example", false).unwrap();
    cache.lock().unwrap().flush().unwrap();

    // Repeated create for the same domain (LAN DNS queries):
    let ip2 = store.create("saved.example", false).unwrap();
    assert_eq!(ip, ip2);

    // Repeated lookup_domain (incoming TPROXY streams):
    let dom = store.lookup_domain(ip).unwrap();
    assert_eq!(dom, "saved.example");

    // Close and reopen cache to simulate router reboot:
    drop((store, cache));
    let cache = Arc::new(Mutex::new(
        CacheFile::open(options.clone()).unwrap().unwrap(),
    ));
    let reopened = pool();
    reopened.attach_cache(Some(cache.clone()));

    // Cold lookup from disk promotes to memory:
    assert_eq!(reopened.lookup_domain(ip).as_deref(), Some("saved.example"));

    // Repeated create for saved.example:
    assert_eq!(reopened.create("saved.example", false).unwrap(), ip);

    let _ = std::fs::remove_file(options.path);
}
