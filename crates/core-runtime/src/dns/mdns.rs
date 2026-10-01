//! mDNS lookups (RFC 6762), the `dns` server type `mdns` and the local-zone
//! predicate the reference uses to answer `.local` names from the LAN.
//!
//! One query per interface and family goes out to the multicast group; the
//! answers that come back are merged into a single response. The reference
//! (`dns/transport/mdns`) does exactly this, down to stripping the mDNS class
//! bits and keeping the first deadline that yields records.

use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{RData, Record, RecordType};

/// Every mDNS packet comes from and goes to this port.
pub const PORT: u16 = 5353;
/// RFC 6762 group for IPv4.
pub const GROUP_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
/// RFC 6762 group for IPv6.
pub const GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);

/// The reference's `mdnsLocalZones`: names that belong on the LAN rather than
/// to the recursive resolver, spelled with the trailing dot it compares with.
const LOCAL_ZONES: [&str; 6] = [
    "local.",
    "254.169.in-addr.arpa.",
    "8.e.f.ip6.arpa.",
    "9.e.f.ip6.arpa.",
    "a.e.f.ip6.arpa.",
    "b.e.f.ip6.arpa.",
];

/// Whether a name is one of the zones mDNS owns. The reference's `IsLocalDomain`
/// is `CanonicalName(name)` — lower-cased, one trailing dot — then a suffix
/// test, so `Printer.local.` and `printer.LOCAL` both land here and
/// `notlocal.` does not.
pub fn is_local_domain(name: &str) -> bool {
    let canonical = format!("{}.", super::codec::normalize_name(name));
    LOCAL_ZONES
        .iter()
        .any(|zone| canonical == *zone || canonical.ends_with(&format!(".{zone}")))
}

/// One interface to ask, with the addresses multicast needs.
#[derive(Debug, Clone)]
pub struct Interface {
    pub name: String,
    pub v4: Option<Ipv4Addr>,
    pub v6: Option<Ipv6Addr>,
}

/// The interfaces to query: the ones named in the config, or every interface
/// with an address when the config names none.
pub fn interfaces(filter: &[String]) -> io::Result<Vec<Interface>> {
    let mut out: Vec<Interface> = Vec::new();
    for entry in if_addrs::get_if_addrs()? {
        let name = entry.name.clone();
        if !filter.is_empty() && !filter.contains(&name) {
            continue;
        }
        if out.iter().all(|iface| iface.name != name) {
            out.push(Interface {
                name: name.clone(),
                v4: None,
                v6: None,
            });
        }
        let slot = out
            .iter_mut()
            .find(|iface| iface.name == name)
            .expect("just inserted");
        match entry.addr {
            if_addrs::IfAddr::V4(addr) => {
                slot.v4.get_or_insert(addr.ip);
            }
            if_addrs::IfAddr::V6(addr) => {
                slot.v6.get_or_insert(addr.ip);
            }
        }
    }
    // loopback cannot carry a multicast answer, and the reference skips
    // interfaces without a usable address the same way
    out.retain(|iface| iface.v4.is_some() || iface.v6.is_some());
    Ok(out)
}

/// The query as it goes on the wire: the caller's message with the mDNS
/// unicast-response bit cleared (`stripQuestionClass` in the reference), which
/// is what asks for a multicast answer.
pub fn query(raw: &[u8]) -> io::Result<Vec<u8>> {
    let mut msg = super::codec::parse_message(raw)?;
    msg.metadata.message_type = MessageType::Query;
    msg.metadata.op_code = OpCode::Query;
    msg.metadata.response_code = ResponseCode::NoError;
    msg.metadata.authoritative = false;
    msg.metadata.recursion_desired = false;
    for question in &mut msg.queries {
        question.mdns_unicast_response = false;
    }
    msg.to_vec()
        .map_err(|e| io::Error::other(format!("mdns: encode query: {e}")))
}

fn first_question(msg: &Message) -> io::Result<Query> {
    msg.queries
        .first()
        .cloned()
        .ok_or_else(|| io::Error::other("mdns: query has no question"))
}

fn matches_question(msg: &Message, question: &Query) -> bool {
    if msg.queries.iter().any(|q| {
        q.name() == question.name()
            && q.query_type() == question.query_type()
            && u16::from(q.query_class()) == u16::from(question.query_class())
    }) {
        return true;
    }
    // a responder that echoes no question at all still answers us if it holds
    // a record for the name we asked about
    let record_matches = |record: &Record<RData>| {
        record.name == *question.name()
            && (question.query_type() == RecordType::ANY
                || record.record_type() == question.query_type()
                || record.record_type() == RecordType::CNAME)
    };
    msg.answers.iter().any(record_matches)
        || msg.authorities.iter().any(record_matches)
        || msg.additionals.iter().any(record_matches)
}

/// Whether a packet is an answer to our question: a NOERROR response that
/// either echoes the question or carries a record for it. The reference's
/// `validResponse`, without the mDNS-only opcode check it shares with QU.
pub fn valid_response(raw: &[u8], question: &Query) -> bool {
    let Ok(msg) = Message::from_vec(raw) else {
        return false;
    };
    if msg.metadata.message_type != MessageType::Response
        || msg.metadata.op_code != OpCode::Query
        || msg.metadata.response_code != ResponseCode::NoError
    {
        return false;
    }
    matches_question(&msg, question)
}

/// Merge every response into one, keeping the first copy of each record, and
/// answer with that. `id` is the caller's transaction id, which the response
/// carries back. Returns `None` when nothing arrived.
pub fn merge(responses: &[Vec<u8>], id: u16) -> io::Result<Option<Vec<u8>>> {
    let mut out = Message::new(id, MessageType::Response, OpCode::Query);
    out.metadata.authoritative = true;
    out.metadata.recursion_desired = false;
    let mut seen: HashSet<String> = HashSet::new();
    for raw in responses {
        let Ok(msg) = Message::from_vec(raw) else {
            continue;
        };
        for section in 0..3 {
            let records = match section {
                0 => &msg.answers,
                1 => &msg.authorities,
                _ => &msg.additionals,
            };
            for record in records {
                // `record.String()` is the key the reference deduplicates on;
                // the class bit is already off, so two copies look the same
                if !seen.insert(record.to_string()) {
                    continue;
                }
                let mut record = record.clone();
                // and the cache-flush bit stays off in what we hand back
                record.mdns_cache_flush = false;
                match section {
                    0 => out.answers.push(record),
                    1 => out.authorities.push(record),
                    _ => out.additionals.push(record),
                }
            }
        }
        if out.queries.is_empty() && msg.queries.len() == 1 {
            let mut question = msg.queries[0].clone();
            question.mdns_unicast_response = false;
            out.add_query(question);
        }
    }
    if out.answers.is_empty() && out.authorities.is_empty() && out.additionals.is_empty() {
        return Ok(None);
    }
    out.to_vec()
        .map(Some)
        .map_err(|e| io::Error::other(format!("mdns: encode response: {e}")))
}

/// Ask every interface, and merge whatever answers arrive before the deadline.
/// The reference gives each target the whole deadline and takes the first one
/// with records; here they all run at once and the merge is the union, which is
/// the same answer for the one-interface case that matters and strictly more
/// complete for the rest.
pub async fn exchange(raw: &[u8], ifaces: &[Interface], timeout: Duration) -> io::Result<Vec<u8>> {
    if ifaces.is_empty() {
        return Err(io::Error::other("mdns: missing usable mDNS interfaces"));
    }
    let msg = super::codec::parse_message(raw)?;
    let question = first_question(&msg)?;
    let query = query(raw)?;
    let deadline = Instant::now() + timeout;
    let id = msg.metadata.id;
    let mut tasks = Vec::with_capacity(ifaces.len() * 2);
    for iface in ifaces {
        if iface.v4.is_some() {
            let query = query.clone();
            let question = question.clone();
            let iface = iface.clone();
            tasks.push(tokio::spawn(async move {
                ask(&iface, false, &query, &question, id, deadline).await
            }));
        }
        if iface.v6.is_some() {
            let query = query.clone();
            let question = question.clone();
            let iface = iface.clone();
            tasks.push(tokio::spawn(async move {
                ask(&iface, true, &query, &question, id, deadline).await
            }));
        }
    }
    let mut answers: Vec<Vec<u8>> = Vec::new();
    let mut last_err = None;
    for task in tasks {
        match task.await {
            Ok(Ok(Some(raw))) => answers.push(raw),
            Ok(Ok(None)) => {}
            Ok(Err(e)) => last_err = Some(e),
            Err(e) => last_err = Some(io::Error::other(format!("mdns: query task: {e}"))),
        }
    }
    if let Some(raw) = merge(&answers, msg.metadata.id)? {
        return Ok(raw);
    }
    if let Some(e) = last_err {
        return Err(e);
    }
    Err(io::Error::other("mdns: query timeout"))
}

/// One interface, one family: bind, join, send, and read until the deadline or
/// the first records arrive.
async fn ask(
    iface: &Interface,
    v6: bool,
    query: &[u8],
    question: &Query,
    id: u16,
    deadline: Instant,
) -> io::Result<Option<Vec<u8>>> {
    let socket = socket(iface, v6)?;
    let group = if v6 {
        SocketAddr::new(IpAddr::V6(GROUP_V6), PORT)
    } else {
        SocketAddr::new(IpAddr::V4(GROUP_V4), PORT)
    };
    socket.send_to(query, group).await?;
    let mut answers: Vec<Vec<u8>> = Vec::new();
    let mut buf = vec![0u8; 65535];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        let Ok(received) = tokio::time::timeout(left, socket.recv_from(&mut buf)).await else {
            break;
        };
        let (n, from) = received?;
        // RFC 6762 6: only a responder on the mDNS port may answer
        if from.port() != PORT {
            continue;
        }
        if !valid_response(&buf[..n], question) {
            continue;
        }
        answers.push(buf[..n].to_vec());
        // one response is enough on a single interface; a second may hold the
        // rest of an A/AAAA set, so read one more and then stop
        if answers.len() >= 2 {
            break;
        }
    }
    if answers.is_empty() {
        return Ok(None);
    }
    merge(&answers, id)
}

fn socket(iface: &Interface, v6: bool) -> io::Result<tokio::net::UdpSocket> {
    socket_on(iface, v6, 0)
}

/// The socket an mDNS query rides: joined to the group on that interface, with
/// multicast looping on so a responder on this host sees the query. The
/// reference binds an ephemeral port and relies on the host's multicast-all
/// default; joining the group as well is what RFC 6762 asks for and what
/// Windows requires.
fn socket_on(iface: &Interface, v6: bool, port: u16) -> io::Result<tokio::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = if v6 { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_nonblocking(true)?;
    // RFC 6762 6: more than one responder may listen on 5353 on one host, so
    // every mDNS socket allows the address to be shared
    socket.set_reuse_address(true)?;
    if v6 {
        // the IPv6 group APIs take an interface index, not an address
        if let Some(index) = interface_index(&iface.name) {
            let _ = socket.set_multicast_loop_v6(true);
            let _ = socket.set_multicast_hops_v6(255);
            let _ = socket.join_multicast_v6(&GROUP_V6, index);
            let _ = socket.set_multicast_if_v6(index);
        }
    } else if let Some(addr) = iface.v4 {
        let _ = socket.set_multicast_loop_v4(true);
        let _ = socket.set_multicast_ttl_v4(255);
        let _ = socket.join_multicast_v4(&GROUP_V4, &addr);
        let _ = socket.set_multicast_if_v4(&addr);
    }
    let bind: SocketAddr = if v6 {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
    };
    socket.bind(&bind.into())?;
    tokio::net::UdpSocket::from_std(socket.into())
}

/// The interface index the IPv6 multicast options need. Windows has no
/// `if_nametoindex`, so an IPv6 mDNS query there rides the default route.
#[cfg(not(windows))]
fn interface_index(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    let index = unsafe { libc::if_nametoindex(c.as_ptr()) };
    (index != 0).then_some(index)
}

#[cfg(windows)]
fn interface_index(_name: &str) -> Option<u32> {
    None
}

#[cfg(test)]
use hickory_proto::rr::Name;

/// A responder's answer for `name`, in the shape a real one sends: the question
/// echoed and the addresses in the answer section. Tests use it to stand in for
/// the responder on the LAN.
#[cfg(test)]
pub fn answer(name: &str, qtype: RecordType, addrs: &[IpAddr], ttl: u32) -> io::Result<Vec<u8>> {
    let name = Name::from_utf8(format!("{name}."))
        .map_err(|e| io::Error::other(format!("mdns: bad name {name:?}: {e}")))?;
    let mut msg = Message::new(0, MessageType::Response, OpCode::Query);
    msg.metadata.authoritative = true;
    msg.add_query(Query::query(name.clone(), qtype));
    for addr in addrs {
        let rdata = match addr {
            IpAddr::V4(v4) => RData::A(hickory_proto::rr::rdata::A(*v4)),
            IpAddr::V6(v6) => RData::AAAA(hickory_proto::rr::rdata::AAAA(*v6)),
        };
        msg.answers
            .push(Record::from_rdata(name.clone(), ttl, rdata));
    }
    msg.to_vec()
        .map_err(|e| io::Error::other(format!("mdns: encode answer: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query_for(name: &str) -> Vec<u8> {
        crate::dns::codec::build_query(0x1234, name, RecordType::A).expect("query")
    }

    /// An interface that can carry multicast, or `None` when this machine has none
    /// (a locked-down container) and the socket path cannot be exercised.
    async fn multicast_interface() -> Option<Interface> {
        let ifaces = interfaces(&[]).ok()?;
        ifaces
            .into_iter()
            .find(|iface| iface.v4.is_some_and(|addr| !addr.is_loopback()))
    }

    #[tokio::test]
    async fn the_whole_path_against_a_responder_on_the_same_interface() {
        let Some(iface) = multicast_interface().await else {
            eprintln!("no non-loopback interface: multicast path not exercised here");
            return;
        };
        // The responder has to answer from port 5353, which is what a real one
        // does and what the reader insists on, so it binds the port itself.
        let responder = match socket_on(&iface, false, PORT) {
            Ok(responder) => responder,
            Err(e) => {
                eprintln!("responder socket on port {PORT}: {e}");
                return;
            }
        };
        let query = query(&query_for("printer.local")).expect("mdns query");
        let iface2 = iface.clone();
        let client =
            tokio::spawn(
                async move { exchange(&query, &[iface2], Duration::from_millis(600)).await },
            );

        let mut buf = vec![0u8; 65535];
        let (n, from) = tokio::time::timeout(Duration::from_secs(2), responder.recv_from(&mut buf))
            .await
            .expect("the query reaches a socket joined to the group")
            .expect("responder read");
        assert!(!buf[..n].is_empty(), "a query arrived");
        let seen = Message::from_vec(&buf[..n]).expect("the query parses");
        assert_eq!(
            crate::dns::codec::normalize_name(&seen.queries[0].name().to_string()),
            "printer.local"
        );
        assert!(!seen.queries[0].mdns_unicast_response());
        responder
            .send_to(
                &answer(
                    "printer.local",
                    RecordType::A,
                    &[IpAddr::from([192, 168, 7, 9])],
                    120,
                )
                .expect("answer"),
                from,
            )
            .await
            .expect("responder write");

        let merged = client.await.expect("client task").expect("merged response");
        assert_eq!(
            crate::dns::codec::answer_ips(&merged).expect("ips"),
            vec![IpAddr::from([192, 168, 7, 9])]
        );
        assert_eq!(
            Message::from_vec(&merged).expect("parse").metadata.id,
            0x1234,
            "the caller's transaction id comes back"
        );
    }

    #[tokio::test]
    async fn no_usable_interface_is_an_error_not_a_hang() {
        let err = exchange(&query_for("printer.local"), &[], Duration::from_millis(50))
            .await
            .expect_err("no interface, no answer");
        assert!(err.to_string().contains("missing usable mDNS interfaces"));
    }

    #[test]
    fn local_zones_are_the_reference_five_plus_one() {
        for name in [
            "printer.local",
            "PRINTER.local.",
            "nas.254.169.in-addr.arpa",
            "host.8.e.f.ip6.arpa",
            "x.9.e.f.ip6.arpa",
            "y.a.e.f.ip6.arpa",
            "z.b.e.f.ip6.arpa",
        ] {
            assert!(is_local_domain(name), "{name} should be local");
        }
        for name in [
            "example.com",
            "notlocal",
            "local.example.com",
            "0.e.f.ip6.arpa",
        ] {
            assert!(!is_local_domain(name), "{name} should not be local");
        }
    }

    #[test]
    fn query_clears_the_unicast_response_bit() {
        let mut raw = query_for("printer.local");
        // set 0x8000 on the question class, the bit hickory calls
        // mdns_unicast_response
        let at = raw.len() - 2;
        raw[at] |= 0x80;
        let msg = crate::dns::codec::parse_message(&raw).expect("parse");
        assert!(msg.queries[0].mdns_unicast_response());
        let sent = query(&raw).expect("mdns query");
        let back = crate::dns::codec::parse_message(&sent).expect("reparse");
        assert!(!back.queries[0].mdns_unicast_response());
        assert_eq!(back.queries[0].name(), msg.queries[0].name());
    }

    #[test]
    fn merge_keeps_one_copy_and_echoes_the_question() {
        let a = answer(
            "printer.local",
            RecordType::A,
            &[IpAddr::from([192, 168, 1, 5])],
            120,
        )
        .expect("answer a");
        let b = answer(
            "printer.local",
            RecordType::A,
            &[
                IpAddr::from([192, 168, 1, 5]),
                IpAddr::from([192, 168, 1, 6]),
            ],
            120,
        )
        .expect("answer b");
        let merged = merge(&[a.clone(), b], 0x4321)
            .expect("merge")
            .expect("records");
        let msg = Message::from_vec(&merged).expect("parse merged");
        assert_eq!(msg.metadata.id, 0x4321);
        assert!(msg.metadata.authoritative);
        assert_eq!(msg.queries.len(), 1);
        assert_eq!(
            crate::dns::codec::normalize_name(&msg.queries[0].name().to_string()),
            "printer.local"
        );
        // 192.168.1.5 arrived twice and is kept once
        assert_eq!(msg.answers.len(), 2);
        let ips = crate::dns::codec::answer_ips(&merged).expect("ips");
        assert_eq!(
            ips,
            vec![
                IpAddr::from([192, 168, 1, 5]),
                IpAddr::from([192, 168, 1, 6])
            ]
        );
    }

    #[test]
    fn merge_of_nothing_is_nothing() {
        assert!(merge(&[], 1).expect("merge").is_none());
        assert!(
            merge(
                &[answer("printer.local", RecordType::A, &[], 120).expect("a")],
                1
            )
            .expect("merge")
            .is_none()
        );
    }

    #[test]
    fn a_response_without_a_matching_record_is_not_ours() {
        let question = first_question(
            &crate::dns::codec::parse_message(&query_for("printer.local")).expect("q"),
        )
        .expect("question");
        let other = answer(
            "other.local",
            RecordType::A,
            &[IpAddr::from([10, 0, 0, 1])],
            120,
        )
        .expect("other");
        assert!(!valid_response(&other, &question));
        let ours = answer(
            "printer.local",
            RecordType::A,
            &[IpAddr::from([10, 0, 0, 2])],
            120,
        )
        .expect("ours");
        assert!(valid_response(&ours, &question));
        // garbage is not an answer either, and must not panic
        assert!(!valid_response(&[0xff, 0x00], &question));
        assert!(!valid_response(&[], &question));
    }

    #[test]
    fn the_cache_flush_bit_is_dropped_from_what_we_return() {
        let mut raw = answer(
            "printer.local",
            RecordType::A,
            &[IpAddr::from([10, 0, 0, 3])],
            120,
        )
        .expect("answer");
        // set 0x8000 on the answer record's class
        let at = raw.len() - 12;
        raw[at] |= 0x80;
        let parsed = Message::from_vec(&raw).expect("parse");
        assert!(parsed.answers[0].mdns_cache_flush);
        let merged = merge(&[raw], 7).expect("merge").expect("records");
        let back = Message::from_vec(&merged).expect("reparse");
        assert!(!back.answers[0].mdns_cache_flush);
        assert_eq!(u16::from(back.answers[0].dns_class), 1);
    }
}
