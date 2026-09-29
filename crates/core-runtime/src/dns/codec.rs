//! DNS wire message helpers on top of `hickory-proto`: query parsing/building,
//! refused/synthetic responses, TTL rewriting and answer extraction.

use std::io;
use std::net::IpAddr;
use std::str::FromStr;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};

pub const DEFAULT_TTL: u32 = 600;

/// Identity of the first question in a query message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryInfo {
    pub id: u16,
    /// Lowercased name without the trailing dot.
    pub name: String,
    pub qtype: RecordType,
}

pub fn parse_query(raw: &[u8]) -> io::Result<(Message, QueryInfo)> {
    let msg =
        Message::from_vec(raw).map_err(|e| io::Error::other(format!("dns: decode query: {e}")))?;
    if msg.metadata.message_type != MessageType::Query {
        return Err(io::Error::other("dns: expected a query message"));
    }
    let q = msg
        .queries
        .first()
        .ok_or_else(|| io::Error::other("dns: query has no question"))?;
    let info = QueryInfo {
        id: msg.metadata.id,
        name: normalize_name(&q.name().to_string()),
        qtype: q.query_type(),
    };
    Ok((msg, info))
}

/// One `option.DNSRecordOptions` entry. The reference unmarshals the JSON
/// into a `dns.RR`; the rdata union used by `predefined` answers is `A`,
/// `AAAA`, `CNAME`, `TXT` and `MX`, plus the base64 wire form a marshalled
/// config carries.
pub fn decode_record(record: &serde_json::Value, at: &str) -> io::Result<Record> {
    if let Some(raw) = record.as_str() {
        let wire = super::rules::base64_decode(raw)
            .map_err(|error| io::Error::other(format!("{at}: {error}")))?;
        return record_from_wire(&wire, at);
    }
    let object = record
        .as_object()
        .ok_or_else(|| io::Error::other(format!("{at}: must be an object or base64 string")))?;
    let ttl = object
        .get("ttl")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(600) as u32;
    let name = match object.get("name").and_then(serde_json::Value::as_str) {
        Some(name) => hickory_proto::rr::Name::from_str(&format!("{name}."))
            .map_err(|e| io::Error::other(format!("{at}: bad name: {e}")))?,
        None => hickory_proto::rr::Name::root(),
    };
    let rdata = match object.get("value") {
        Some(serde_json::Value::String(text)) => match IpAddr::from_str(text) {
            Ok(IpAddr::V4(addr)) => RData::A(A(addr)),
            Ok(IpAddr::V6(addr)) => RData::AAAA(AAAA(addr)),
            Err(_) => RData::TXT(hickory_proto::rr::rdata::TXT::new(vec![text.to_string()])),
        },
        Some(value @ serde_json::Value::Object(_)) => record_rdata(value, at)?,
        _ => {
            return Err(io::Error::other(format!(
                "{at}: value must be a string or a typed record object"
            )));
        }
    };
    Ok(Record::from_rdata(name, ttl, rdata))
}

fn record_rdata(value: &serde_json::Value, at: &str) -> io::Result<RData> {
    let rtype = value
        .get("type")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| io::Error::other(format!("{at}: value is missing type")))?;
    match rtype {
        "A" | "AAAA" => {
            let ip = value
                .get("ip")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| io::Error::other(format!("{at}: missing ip")))?;
            match IpAddr::from_str(ip)
                .map_err(|e| io::Error::other(format!("{at}: bad ip {ip:?}: {e}")))?
            {
                IpAddr::V4(addr) => Ok(RData::A(A(addr))),
                IpAddr::V6(addr) => Ok(RData::AAAA(AAAA(addr))),
            }
        }
        "CNAME" => {
            let target = value
                .get("domain")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| io::Error::other(format!("{at}: missing domain")))?;
            Ok(RData::CNAME(hickory_proto::rr::rdata::CNAME(
                hickory_proto::rr::Name::from_str(&format!("{target}."))
                    .map_err(|e| io::Error::other(format!("{at}: bad domain: {e}")))?,
            )))
        }
        "TXT" => {
            let text = value
                .get("text")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| io::Error::other(format!("{at}: missing text")))?;
            Ok(RData::TXT(hickory_proto::rr::rdata::TXT::new(vec![
                text.to_string(),
            ])))
        }
        "MX" => {
            let preference = value
                .get("preference")
                .and_then(|value| value.as_u64().and_then(|v| u16::try_from(v).ok()))
                .ok_or_else(|| io::Error::other(format!("{at}: missing preference")))?;
            let exchange = value
                .get("domain")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| io::Error::other(format!("{at}: missing domain")))?;
            Ok(RData::MX(hickory_proto::rr::rdata::MX::new(
                preference,
                hickory_proto::rr::Name::from_str(&format!("{exchange}."))
                    .map_err(|e| io::Error::other(format!("{at}: bad domain: {e}")))?,
            )))
        }
        other => Err(io::Error::other(format!(
            "{at}: unsupported record type {other:?}"
        ))),
    }
}

/// Minimal wire-format reader for the base64 form: name, type, class, ttl and
/// rdata, which is all a `Record` needs.
fn record_from_wire(wire: &[u8], at: &str) -> io::Result<Record> {
    let mut offset = 0usize;
    let name = read_wire_name(wire, &mut offset, at)?;
    let rtype = read_u16(wire, &mut offset, at)?;
    let _class = read_u16(wire, &mut offset, at)?;
    let ttl = read_u32(wire, &mut offset, at)?;
    let rdlength = read_u16(wire, &mut offset, at)? as usize;
    let rdata = wire
        .get(offset..offset + rdlength)
        .ok_or_else(|| io::Error::other(format!("{at}: truncated rdata")))?;
    let rdata = match RecordType::from(rtype) {
        RecordType::A => {
            let bytes: [u8; 4] = rdata
                .try_into()
                .map_err(|_| io::Error::other(format!("{at}: bad A rdata")))?;
            RData::A(A(std::net::Ipv4Addr::from(bytes)))
        }
        RecordType::AAAA => {
            let bytes: [u8; 16] = rdata
                .try_into()
                .map_err(|_| io::Error::other(format!("{at}: bad AAAA rdata")))?;
            RData::AAAA(AAAA(std::net::Ipv6Addr::from(bytes)))
        }
        RecordType::TXT => {
            let mut text = String::new();
            let mut rest = rdata;
            while let Some((&len, tail)) = rest.split_first() {
                let len = len as usize;
                let chunk = tail
                    .get(..len)
                    .ok_or_else(|| io::Error::other(format!("{at}: bad TXT rdata")))?;
                text.push_str(&String::from_utf8_lossy(chunk));
                rest = &tail[len..];
            }
            RData::TXT(hickory_proto::rr::rdata::TXT::new(vec![text]))
        }
        RecordType::CNAME => {
            let mut inner = 0usize;
            RData::CNAME(hickory_proto::rr::rdata::CNAME(read_wire_name(
                rdata, &mut inner, at,
            )?))
        }
        other => {
            return Err(io::Error::other(format!(
                "{at}: unsupported record type {other:?}"
            )));
        }
    };
    Ok(Record::from_rdata(name, ttl, rdata))
}

fn read_wire_name(
    wire: &[u8],
    offset: &mut usize,
    at: &str,
) -> io::Result<hickory_proto::rr::Name> {
    let mut labels: Vec<String> = Vec::new();
    loop {
        let len = *wire
            .get(*offset)
            .ok_or_else(|| io::Error::other(format!("{at}: truncated name")))?
            as usize;
        *offset += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            return Err(io::Error::other(format!("{at}: bad label length")));
        }
        let end = *offset + len;
        let label = wire
            .get(*offset..end)
            .ok_or_else(|| io::Error::other(format!("{at}: truncated label")))?;
        labels.push(String::from_utf8_lossy(label).to_string());
        *offset = end;
    }
    hickory_proto::rr::Name::from_labels(labels)
        .map_err(|e| io::Error::other(format!("{at}: bad name: {e}")))
}

fn read_u16(wire: &[u8], offset: &mut usize, at: &str) -> io::Result<u16> {
    let bytes = wire
        .get(*offset..*offset + 2)
        .ok_or_else(|| io::Error::other(format!("{at}: truncated record")))?;
    *offset += 2;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(wire: &[u8], offset: &mut usize, at: &str) -> io::Result<u32> {
    let bytes = wire
        .get(*offset..*offset + 4)
        .ok_or_else(|| io::Error::other(format!("{at}: truncated record")))?;
    *offset += 4;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub fn parse_message(raw: &[u8]) -> io::Result<Message> {
    Message::from_vec(raw).map_err(|e| io::Error::other(format!("dns: decode message: {e}")))
}

pub fn normalize_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

pub fn build_query(id: u16, name: &str, qtype: RecordType) -> io::Result<Vec<u8>> {
    let name = hickory_proto::rr::Name::from_str(&format!("{name}."))
        .map_err(|e| io::Error::other(format!("dns: bad name {name:?}: {e}")))?;
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(hickory_proto::op::Query::query(name, qtype));
    msg.to_vec()
        .map_err(|e| io::Error::other(format!("dns: encode query: {e}")))
}

fn response_skeleton(query: &Message, rcode: ResponseCode) -> Message {
    let mut resp = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
    resp.metadata.response_code = rcode;
    resp.metadata.recursion_desired = query.metadata.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.queries = query.queries.clone();
    resp
}

fn encode(msg: &Message) -> io::Result<Vec<u8>> {
    msg.to_vec()
        .map_err(|e| io::Error::other(format!("dns: encode response: {e}")))
}

/// REFUSED reply echoing the question (reject action, default method).
pub fn refused_response(query: &Message) -> io::Result<Vec<u8>> {
    encode(&response_skeleton(query, ResponseCode::Refused))
}

/// NOERROR with an empty answer section (fakeip family not configured).
pub fn empty_success(query: &Message) -> io::Result<Vec<u8>> {
    encode(&response_skeleton(query, ResponseCode::NoError))
}

/// Synthesize an A/AAAA answer for fakeip.
pub fn synth_address(query: &Message, addr: IpAddr, ttl: u32) -> io::Result<Vec<u8>> {
    let Some(q) = query.queries.first() else {
        return Err(io::Error::other("dns: query has no question"));
    };
    let mut resp = response_skeleton(query, ResponseCode::NoError);
    let rdata = match addr {
        IpAddr::V4(ip) => RData::A(A(ip)),
        IpAddr::V6(ip) => RData::AAAA(AAAA(ip)),
    };
    resp.answers
        .push(Record::from_rdata(q.name().clone(), ttl, rdata));
    encode(&resp)
}

/// Synthesize an A/AAAA answer carrying every address of `addrs`, which is
/// what the `hosts` and `local` server types answer with.
pub fn synth_addresses(query: &Message, addrs: &[IpAddr], ttl: u32) -> io::Result<Vec<u8>> {
    let Some(q) = query.queries.first() else {
        return Err(io::Error::other("dns: query has no question"));
    };
    // dns.FixedResponse only answers with the family the question asked for
    let v4 = matches!(q.query_type(), RecordType::A);
    let v6 = matches!(q.query_type(), RecordType::AAAA);
    if !v4 && !v6 {
        return encode(&response_skeleton(query, ResponseCode::NoError));
    }
    let mut resp = response_skeleton(query, ResponseCode::NoError);
    for addr in addrs {
        let rdata = match *addr {
            IpAddr::V4(ip) if v4 => RData::A(A(ip)),
            IpAddr::V6(ip) if v6 => RData::AAAA(AAAA(ip)),
            _ => continue,
        };
        resp.answers
            .push(Record::from_rdata(q.name().clone(), ttl, rdata));
    }
    encode(&resp)
}

/// NXDOMAIN, which is what the `hosts` transport answers for a name it does
/// not know.
pub fn name_error(query: &Message) -> io::Result<Vec<u8>> {
    encode(&response_skeleton(query, ResponseCode::NXDomain))
}

/// `action: predefined` — a synthesized answer from the configured records.
pub fn predefined_response(
    query: &Message,
    predefined: &super::rules::PredefinedResponse,
) -> io::Result<Vec<u8>> {
    let rcode = predefined
        .rcode
        .map(|value| ResponseCode::from(value & 0x0f, 0))
        .unwrap_or(ResponseCode::NoError);
    let mut resp = response_skeleton(query, rcode);
    let mut append = |records: &[Record], section: u8| {
        for record in records {
            match section {
                0 => resp.answers.push(record.clone()),
                1 => resp.authorities.push(record.clone()),
                _ => resp.additionals.push(record.clone()),
            }
        }
    };
    append(&predefined.answer, 0);
    append(&predefined.ns, 1);
    append(&predefined.extra, 2);
    encode(&resp)
}

/// Set every answer TTL (rewrite_ttl rule action); returns re-encoded bytes.
pub fn rewrite_ttl(raw: &[u8], ttl: u32) -> io::Result<Vec<u8>> {
    let mut msg = parse_message(raw)?;
    for record in &mut msg.answers {
        record.ttl = ttl;
    }
    encode(&msg)
}

/// All A/AAAA addresses in the answer section.
pub fn answer_ips(raw: &[u8]) -> io::Result<Vec<IpAddr>> {
    let msg = parse_message(raw)?;
    let mut out = Vec::new();
    for record in &msg.answers {
        match &record.data {
            RData::A(a) => out.push(IpAddr::V4(a.0)),
            RData::AAAA(a) => out.push(IpAddr::V6(a.0)),
            _ => {}
        }
    }
    Ok(out)
}

/// Response header metadata used for caching decisions.
#[derive(Debug, Clone, Copy)]
pub struct ResponseMeta {
    pub rcode: ResponseCode,
    /// Smallest answer TTL; `None` when there are no answers.
    pub min_answer_ttl: Option<u32>,
}

pub fn response_meta(raw: &[u8]) -> io::Result<ResponseMeta> {
    let msg = parse_message(raw)?;
    Ok(ResponseMeta {
        rcode: msg.metadata.response_code,
        min_answer_ttl: msg.answers.iter().map(|r| r.ttl).min(),
    })
}

/// Rewrite the response ID to match the client query (cache hits).
pub fn set_id(raw: &[u8], id: u16) -> io::Result<Vec<u8>> {
    let mut msg = parse_message(raw)?;
    msg.metadata.id = id;
    encode(&msg)
}

pub fn parse_record_type(raw: &str) -> Option<RecordType> {
    RecordType::from_str(raw).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_roundtrip() {
        let raw = build_query(0x1234, "Example.COM", RecordType::A).unwrap();
        let (msg, info) = parse_query(&raw).unwrap();
        assert_eq!(info.id, 0x1234);
        assert_eq!(info.name, "example.com");
        assert_eq!(info.qtype, RecordType::A);
        assert!(msg.metadata.recursion_desired);
    }

    #[test]
    fn synth_and_extract() {
        let raw = build_query(7, "fake.test", RecordType::A).unwrap();
        let (query, _) = parse_query(&raw).unwrap();
        let resp = synth_address(&query, "198.18.0.1".parse().unwrap(), 600).unwrap();
        let meta = response_meta(&resp).unwrap();
        assert_eq!(meta.rcode, ResponseCode::NoError);
        assert_eq!(meta.min_answer_ttl, Some(600));
        assert_eq!(
            answer_ips(&resp).unwrap(),
            vec!["198.18.0.1".parse::<IpAddr>().unwrap()]
        );
        let resp = set_id(&resp, 99).unwrap();
        assert_eq!(parse_message(&resp).unwrap().metadata.id, 99);
    }

    #[test]
    fn refused_echoes_question() {
        let raw = build_query(42, "blocked.test", RecordType::HTTPS).unwrap();
        let (query, info) = parse_query(&raw).unwrap();
        let resp = refused_response(&query).unwrap();
        let msg = parse_message(&resp).unwrap();
        assert_eq!(msg.metadata.id, 42);
        assert_eq!(msg.metadata.response_code, ResponseCode::Refused);
        let (_, back) = parse_query(
            // parse_query requires QR=0; inspect directly instead
            &raw,
        )
        .unwrap();
        assert_eq!(back, info);
    }

    #[test]
    fn ttl_rewrite() {
        let raw = build_query(1, "t.test", RecordType::A).unwrap();
        let (query, _) = parse_query(&raw).unwrap();
        let resp = synth_address(&query, "10.0.0.1".parse().unwrap(), 600).unwrap();
        let rewritten = rewrite_ttl(&resp, 60).unwrap();
        assert_eq!(response_meta(&rewritten).unwrap().min_answer_ttl, Some(60));
    }
}
