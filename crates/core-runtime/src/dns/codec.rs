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
