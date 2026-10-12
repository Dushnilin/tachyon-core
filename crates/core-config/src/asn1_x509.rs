//! Go `encoding/asn1` + `crypto/x509` emulation for masque key parsing.
//!
//! Ports the go1.26.8 parse engine closely enough to reproduce the exact
//! reference error texts, e.g. `x509: failed to parse EC private key:
//! asn1: structure error: tags don't match (16 vs {class:0 tag:1 ...}) ...
//! ecPrivateKey @2`.

use std::cmp::Ordering;
use std::fmt;

// ---------------------------------------------------------------------------
// errors
// ---------------------------------------------------------------------------

pub enum Asn1Err {
    Syntax(String),
    Structural(String),
}

impl fmt::Display for Asn1Err {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Asn1Err::Syntax(m) => write!(f, "asn1: syntax error: {m}"),
            Asn1Err::Structural(m) => write!(f, "asn1: structure error: {m}"),
        }
    }
}

/// Go `fmt.Sprintf("%+v", fieldParameters{})`.
const EMPTY_PARAMS: &str = "{optional:false explicit:false application:false \
private:false defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false}";

// ---------------------------------------------------------------------------
// low-level parsers
// ---------------------------------------------------------------------------

fn parse_base128(b: &[u8], init: usize) -> Result<(i64, usize), Asn1Err> {
    let mut off = init;
    let mut ret: i64 = 0;
    let mut shifted = 0usize;
    while off < b.len() {
        if shifted == 5 {
            return Err(Asn1Err::Structural("base 128 integer too large".into()));
        }
        let c = b[off];
        if shifted == 0 && c == 0x80 {
            return Err(Asn1Err::Syntax("integer is not minimally encoded".into()));
        }
        ret = ret.wrapping_shl(7) | i64::from(c & 0x7f);
        off += 1;
        if c & 0x80 == 0 {
            if ret > i64::from(i32::MAX) {
                return Err(Asn1Err::Structural("base 128 integer too large".into()));
            }
            return Ok((ret, off));
        }
        shifted += 1;
    }
    Err(Asn1Err::Syntax("truncated base 128 integer".into()))
}

struct Tl {
    class: u8,
    compound: bool,
    tag: i64,
    length: usize,
}

fn parse_tl(b: &[u8], init: usize) -> Result<(Tl, usize), Asn1Err> {
    let mut off = init;
    if off >= b.len() {
        return Err(Asn1Err::Syntax(
            "internal error in parseTagAndLength".into(),
        ));
    }
    let first = b[off];
    off += 1;
    let class = first >> 6;
    let compound = first & 0x20 == 0x20;
    let mut tag = i64::from(first & 0x1f);
    if tag == 0x1f {
        let (t, o) = parse_base128(b, off)?;
        tag = t;
        off = o;
        if tag < 0x1f {
            return Err(Asn1Err::Syntax("non-minimal tag".into()));
        }
    }
    if off >= b.len() {
        return Err(Asn1Err::Syntax("truncated tag or length".into()));
    }
    let lb = b[off];
    off += 1;
    let length = if lb & 0x80 == 0 {
        usize::from(lb & 0x7f)
    } else {
        let num = usize::from(lb & 0x7f);
        if num == 0 {
            return Err(Asn1Err::Syntax("indefinite length found (not DER)".into()));
        }
        let mut l: usize = 0;
        for _ in 0..num {
            if off >= b.len() {
                return Err(Asn1Err::Syntax("truncated tag or length".into()));
            }
            let c = b[off];
            off += 1;
            if l >= 1 << 23 {
                return Err(Asn1Err::Structural("length too large".into()));
            }
            l = (l << 8) | usize::from(c);
            if l == 0 {
                return Err(Asn1Err::Structural(
                    "superfluous leading zeros in length".into(),
                ));
            }
        }
        if l < 0x80 {
            return Err(Asn1Err::Structural("non-minimal length".into()));
        }
        l
    };
    Ok((
        Tl {
            class,
            compound,
            tag,
            length,
        },
        off,
    ))
}

fn check_integer(b: &[u8]) -> Result<(), Asn1Err> {
    if b.is_empty() {
        return Err(Asn1Err::Structural("empty integer".into()));
    }
    if b.len() == 1 {
        return Ok(());
    }
    if (b[0] == 0 && b[1] & 0x80 == 0) || (b[0] == 0xff && b[1] & 0x80 == 0x80) {
        return Err(Asn1Err::Structural("integer not minimally-encoded".into()));
    }
    Ok(())
}

fn parse_int64(b: &[u8]) -> Result<i64, Asn1Err> {
    check_integer(b)?;
    if b.len() > 8 {
        return Err(Asn1Err::Structural("integer too large".into()));
    }
    let mut ret: i64 = 0;
    for &c in b {
        ret = (ret << 8) | i64::from(c);
    }
    let shift = 64 - u32::try_from(b.len()).unwrap_or(8) * 8;
    Ok(ret.wrapping_shl(shift).wrapping_shr(shift))
}

/// Returns the right-aligned BIT STRING content bytes.
fn parse_bit_string(b: &[u8]) -> Result<Vec<u8>, Asn1Err> {
    if b.is_empty() {
        return Err(Asn1Err::Syntax("zero length BIT STRING".into()));
    }
    let pad = b[0];
    if pad > 7 || (b.len() == 1 && pad > 0) || (b[b.len() - 1] & ((1u16 << pad) - 1) as u8 != 0) {
        return Err(Asn1Err::Syntax("invalid padding bits in BIT STRING".into()));
    }
    let data = &b[1..];
    if pad == 0 || data.is_empty() {
        return Ok(data.to_vec());
    }
    let mut a = vec![0u8; data.len()];
    a[0] = data[0] >> pad;
    for i in 1..data.len() {
        a[i] = (data[i - 1] << (8 - pad)) | (data[i] >> pad);
    }
    Ok(a)
}

fn parse_oid(b: &[u8]) -> Result<Vec<i64>, Asn1Err> {
    if b.is_empty() {
        return Err(Asn1Err::Syntax("zero length OBJECT IDENTIFIER".into()));
    }
    let (v, mut off) = parse_base128(b, 0)?;
    let (a, c) = if v < 80 {
        (v / 40, v % 40)
    } else {
        (2, v - 80)
    };
    let mut out = vec![a, c];
    while off < b.len() {
        let (v2, o2) = parse_base128(b, off)?;
        out.push(v2);
        off = o2;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// field engine
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub enum Val {
    Int(i64),
    Big(Vec<u8>),
    Bytes(Vec<u8>),
    Bit(Vec<u8>),
    Oid(Vec<i64>),
    Raw(Vec<u8>),
    List(Vec<Option<Val>>),
}

impl Val {
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Val::Int(n) => Some(*n),
            _ => None,
        }
    }
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Val::Bytes(b) | Val::Bit(b) => Some(b),
            _ => None,
        }
    }
    pub fn as_oid(&self) -> Option<&[i64]> {
        match self {
            Val::Oid(o) => Some(o),
            _ => None,
        }
    }
    pub fn as_list(&self) -> Option<&[Option<Val>]> {
        match self {
            Val::List(l) => Some(l),
            _ => None,
        }
    }
    pub fn as_raw(&self) -> Option<&[u8]> {
        match self {
            Val::Raw(r) => Some(r),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
pub enum Kind {
    Int,
    Big,
    Octet,
    BitStr,
    Oid,
    Raw,
    Struct(&'static [Field]),
    SeqOf(&'static [Field]),
}

#[derive(Clone, Copy)]
pub struct Field {
    pub name: &'static str,
    pub kind: Kind,
    pub optional: bool,
    pub explicit: Option<i64>,
}

const fn f(name: &'static str, kind: Kind) -> Field {
    Field {
        name,
        kind,
        optional: false,
        explicit: None,
    }
}

const fn f_opt(name: &'static str, kind: Kind) -> Field {
    Field {
        name,
        kind,
        optional: true,
        explicit: None,
    }
}

const fn f_exp(name: &'static str, kind: Kind, tag: i64) -> Field {
    Field {
        name,
        kind,
        optional: true,
        explicit: Some(tag),
    }
}

fn parse_field(
    b: &[u8],
    init: usize,
    field: &Field,
    depth: usize,
) -> Result<(usize, Option<Val>), Asn1Err> {
    if depth > 10_000 {
        return Err(Asn1Err::Structural("nesting depth exceeded".into()));
    }
    if init == b.len() {
        return if field.optional {
            Ok((init, None))
        } else {
            Err(Asn1Err::Syntax("sequence truncated".into()))
        };
    }
    let (mut t, mut off) = parse_tl(b, init)?;
    if let Some(tag) = field.explicit {
        if off == b.len() {
            return Err(Asn1Err::Structural("explicit tag has no child".into()));
        }
        if t.class == 2 && t.tag == tag && (t.length == 0 || t.compound) {
            if t.length > 0 {
                let (t2, o2) = parse_tl(b, off)?;
                t = t2;
                off = o2;
            } else {
                return Err(Asn1Err::Structural(
                    "zero length explicit tag was not an asn1.Flag".into(),
                ));
            }
        } else if field.optional {
            return Ok((init, None));
        } else {
            return Err(Asn1Err::Structural(
                "explicitly tagged member didn't match".into(),
            ));
        }
    }
    let (expected, compound_type, match_any) = match field.kind {
        Kind::Raw => (0i64, false, true),
        Kind::Int | Kind::Big => (2, false, false),
        Kind::BitStr => (3, false, false),
        Kind::Octet => (4, false, false),
        Kind::Oid => (6, false, false),
        Kind::Struct(_) | Kind::SeqOf(_) => (16, true, false),
    };
    if !match_any && (t.class != 0 || t.tag != expected || t.compound != compound_type) {
        if field.optional {
            return Ok((init, None));
        }
        return Err(Asn1Err::Structural(format!(
            "tags don't match ({expected} vs {{class:{} tag:{} length:{} isCompound:{}}}) {} {} @{}",
            t.class, t.tag, t.length, t.compound, EMPTY_PARAMS, field.name, off
        )));
    }
    let end = off
        .checked_add(t.length)
        .filter(|&e| e <= b.len())
        .ok_or_else(|| Asn1Err::Syntax("data truncated".into()))?;
    let inner = &b[off..end];
    let val = match field.kind {
        Kind::Raw => Val::Raw(b[init..end].to_vec()),
        Kind::Oid => Val::Oid(parse_oid(inner)?),
        Kind::BitStr => Val::Bit(parse_bit_string(inner)?),
        Kind::Int => Val::Int(parse_int64(inner)?),
        Kind::Big => {
            check_integer(inner)?;
            Val::Big(inner.to_vec())
        }
        Kind::Octet => Val::Bytes(inner.to_vec()),
        Kind::Struct(fields) => {
            let mut vals = Vec::with_capacity(fields.len());
            let mut io = 0usize;
            for sub in fields.iter() {
                let (o2, v) = parse_field(inner, io, sub, depth + 1)?;
                io = o2;
                vals.push(v);
            }
            // extra trailing bytes inside a SEQUENCE are allowed (x509 style)
            Val::List(vals)
        }
        Kind::SeqOf(fields) => parse_seq_of(inner, fields, depth + 1)?,
    };
    Ok((end, Some(val)))
}

fn parse_seq_of(b: &[u8], elem: &'static [Field], depth: usize) -> Result<Val, Asn1Err> {
    let mut num = 0usize;
    let mut off = 0usize;
    while off < b.len() {
        let (t, o2) = parse_tl(b, off)?;
        if t.class != 0 || t.tag != 16 || !t.compound {
            return Err(Asn1Err::Structural("sequence tag mismatch".into()));
        }
        let end = o2
            .checked_add(t.length)
            .filter(|&e| e <= b.len())
            .ok_or_else(|| Asn1Err::Syntax("truncated sequence".into()))?;
        off = end;
        num += 1;
    }
    let sub = Field {
        name: "",
        kind: Kind::Struct(elem),
        optional: false,
        explicit: None,
    };
    let mut vals = Vec::with_capacity(num);
    let mut io = 0usize;
    for _ in 0..num {
        let (o2, v) = parse_field(b, io, &sub, depth)?;
        io = o2;
        vals.push(v);
    }
    Ok(Val::List(vals))
}

/// Top-level `asn1.Unmarshal` into a struct: parses one outer SEQUENCE,
/// returns the offset after it plus parsed field values (trailing rest allowed
/// unless the caller checks).
fn parse_tlv_struct(
    b: &[u8],
    name: &'static str,
    fields: &'static [Field],
    depth: usize,
) -> Result<(usize, Vec<Option<Val>>), Asn1Err> {
    if depth > 10_000 {
        return Err(Asn1Err::Structural("nesting depth exceeded".into()));
    }
    if b.is_empty() {
        return Err(Asn1Err::Syntax("sequence truncated".into()));
    }
    let (t, off) = parse_tl(b, 0)?;
    if t.class != 0 || t.tag != 16 || !t.compound {
        return Err(Asn1Err::Structural(format!(
            "tags don't match (16 vs {{class:{} tag:{} length:{} isCompound:{}}}) {} {} @{}",
            t.class, t.tag, t.length, t.compound, EMPTY_PARAMS, name, off
        )));
    }
    let end = off
        .checked_add(t.length)
        .filter(|&e| e <= b.len())
        .ok_or_else(|| Asn1Err::Syntax("data truncated".into()))?;
    let inner = &b[off..end];
    let mut vals = Vec::with_capacity(fields.len());
    let mut io = 0usize;
    for field in fields.iter() {
        let (o2, v) = parse_field(inner, io, field, depth + 1)?;
        io = o2;
        vals.push(v);
    }
    Ok((end, vals))
}

// ---------------------------------------------------------------------------
// structure shapes
// ---------------------------------------------------------------------------

const ALG_ID_FIELDS: &[Field] = &[
    f("ObjectIdentifier", Kind::Oid),
    f_opt("RawValue", Kind::Raw),
];

const SEC1_FIELDS: &[Field] = &[
    f("int", Kind::Int),
    f("", Kind::Octet),
    f_exp("ObjectIdentifier", Kind::Oid, 0),
    f_exp("BitString", Kind::BitStr, 1),
];

const PKCS8_FIELDS: &[Field] = &[
    f("int", Kind::Int),
    f("AlgorithmIdentifier", Kind::Struct(ALG_ID_FIELDS)),
    f("", Kind::Octet),
];

const PKCS1_PRIV_FIELDS: &[Field] = &[
    f("int", Kind::Int),
    f("", Kind::Big),
    f("", Kind::Big),
    f("", Kind::Big),
    f("", Kind::Big),
    f("", Kind::Big),
    f("", Kind::Big),
    f("", Kind::Big),
    f("", Kind::Big),
    f_opt("", Kind::SeqOf(PKCS1_ADD_FIELDS)),
];

const PKCS1_ADD_FIELDS: &[Field] = &[f("", Kind::Big), f("", Kind::Big), f("", Kind::Big)];

const PKCS1_PUB_FIELDS: &[Field] = &[f("", Kind::Big), f("int", Kind::Int)];

const PKIX_FIELDS: &[Field] = &[
    f("AlgorithmIdentifier", Kind::Struct(ALG_ID_FIELDS)),
    f("BitString", Kind::BitStr),
];

const RSA_OID: &[i64] = &[1, 2, 840, 113549, 1, 1, 1];
const EC_OID: &[i64] = &[1, 2, 840, 10045, 2, 1];

// ---------------------------------------------------------------------------
// curve tables (go1.26.8 crypto/elliptic, SP 800-186)
// ---------------------------------------------------------------------------

struct CurveDef {
    name: &'static str,
    size: usize,
    oid: &'static [i64],
    n_hex: &'static str,
    p_hex: &'static str,
}

const CURVES: &[CurveDef] = &[
    CurveDef {
        name: "P-224",
        size: 28,
        oid: &[1, 3, 132, 0, 33],
        n_hex: "ffffffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d",
        p_hex: "ffffffffffffffffffffffffffffffff000000000000000000000001",
    },
    CurveDef {
        name: "P-256",
        size: 32,
        oid: &[1, 2, 840, 10045, 3, 1, 7],
        n_hex: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        p_hex: "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    },
    CurveDef {
        name: "P-384",
        size: 48,
        oid: &[1, 3, 132, 0, 34],
        n_hex: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffc7634d81\
f4372ddf581a0db248b0a77aecec196accc52973",
        p_hex: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
ffffffff0000000000000000ffffffff",
    },
    CurveDef {
        name: "P-521",
        size: 66,
        oid: &[1, 3, 132, 0, 35],
        n_hex: "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
fa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
        p_hex: "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    },
];

fn hex_bytes(s: &str) -> Vec<u8> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap_or(0))
        .collect()
}

fn curve_from_oid(oid: &[i64]) -> Option<&'static CurveDef> {
    CURVES.iter().find(|c| c.oid == oid)
}

fn bi_cmp(a: &[u8], b: &[u8]) -> Ordering {
    let az = a
        .iter()
        .position(|&x| x != 0)
        .unwrap_or_else(|| a.len().saturating_sub(1));
    let bz = b
        .iter()
        .position(|&x| x != 0)
        .unwrap_or_else(|| b.len().saturating_sub(1));
    let a = &a[az..];
    let b = &b[bz..];
    if a.len() != b.len() {
        return a.len().cmp(&b.len());
    }
    a.cmp(b)
}

fn bi_mul(a: &[u8], b: &[u8]) -> Vec<u8> {
    if a.is_empty() || b.is_empty() || a.iter().all(|&x| x == 0) || b.iter().all(|&x| x == 0) {
        return vec![0];
    }
    let mut out = vec![0u8; a.len() + b.len()];
    for i in (0..a.len()).rev() {
        if a[i] == 0 {
            continue;
        }
        let mut carry = 0u32;
        for j in (0..b.len()).rev() {
            let t = u32::from(a[i]) * u32::from(b[j]) + u32::from(out[i + j + 1]) + carry;
            out[i + j + 1] = t as u8;
            carry = t >> 8;
        }
        let mut k = i;
        while carry > 0 {
            let t = u32::from(out[k]) + carry;
            out[k] = t as u8;
            carry = t >> 8;
            if k == 0 {
                break;
            }
            k -= 1;
        }
    }
    out
}

fn bi_add(a: &[u8], b: &[u8]) -> Vec<u8> {
    let (la, lb) = (a.len(), b.len());
    let n = la.max(lb);
    let mut out = vec![0u8; n + 1];
    let mut carry = 0u32;
    for k in 0..n {
        let x = if k < la { u32::from(a[la - 1 - k]) } else { 0 };
        let y = if k < lb { u32::from(b[lb - 1 - k]) } else { 0 };
        let t = x + y + carry;
        out[n - k] = t as u8;
        carry = t >> 8;
    }
    out[0] = carry as u8;
    out
}

/// a - b, requires a >= b, big-endian.
fn bi_sub(a: &[u8], b: &[u8]) -> Vec<u8> {
    let la = a.len();
    let lb = b.len();
    let mut out = vec![0u8; la];
    let mut borrow = 0i32;
    for k in 0..la {
        let x = i32::from(a[la - 1 - k]);
        let y = if k < lb { i32::from(b[lb - 1 - k]) } else { 0 };
        let mut d = x - y - borrow;
        if d < 0 {
            d += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out[la - 1 - k] = d as u8;
    }
    out
}

fn bi_shl1(v: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; v.len() + 1];
    let mut carry = 0u8;
    for i in (0..v.len()).rev() {
        out[i + 1] = (v[i] << 1) | carry;
        carry = v[i] >> 7;
    }
    out[0] = carry;
    out
}

/// v mod m via binary long division (v, m big-endian, m > 0).
fn bi_mod(v: &[u8], m: &[u8]) -> Vec<u8> {
    if bi_cmp(v, m) != Ordering::Less {
        let mut acc: Vec<u8> = Vec::new();
        for &byte in v {
            for bit in (0..8).rev() {
                acc = bi_shl1(&acc);
                if (byte >> bit) & 1 == 1 {
                    let last = acc.last_mut().unwrap();
                    *last |= 1;
                }
                if bi_cmp(&acc, m) != Ordering::Less {
                    acc = bi_sub(&acc, m);
                }
            }
        }
        acc
    } else {
        v.to_vec()
    }
}

fn strip(v: &[u8]) -> Vec<u8> {
    let z = v.iter().position(|&x| x != 0).unwrap_or(v.len());
    if z == v.len() {
        vec![0]
    } else {
        v[z..].to_vec()
    }
}

fn p256_on_curve(x: &[u8], y: &[u8]) -> bool {
    let p = hex_bytes(CURVES[1].p_hex);
    let b = hex_bytes("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");
    let lhs = strip(&bi_mod(&bi_mul(y, y), &p));
    let x2 = bi_mod(&bi_mul(x, x), &p);
    let x3 = bi_mod(&bi_mul(&x2, x), &p);
    let three_x = {
        let s1 = bi_add(x, x);
        let s2 = bi_add(&s1, x);
        bi_mod(&s2, &p)
    };
    // x3 - three_x mod p
    let mut t = if bi_cmp(&x3, &three_x) == Ordering::Less {
        bi_add(&x3, &p)
    } else {
        x3.clone()
    };
    t = strip(&bi_sub(&t, &three_x));
    let rhs = strip(&bi_mod(&bi_add(&t, &b), &p));
    bi_cmp(&lhs, &rhs) == Ordering::Equal
}

// ---------------------------------------------------------------------------
// x509 private key (SEC 1)
// ---------------------------------------------------------------------------

/// `x509.ParseECPrivateKey`; on success returns the padded scalar bytes.
pub fn parse_ec_private(der: &[u8]) -> Result<Vec<u8>, String> {
    match parse_tlv_struct(der, "ecPrivateKey", SEC1_FIELDS, 0) {
        Ok((_, vals)) => {
            let version = vals[0].as_ref().and_then(Val::as_int).unwrap_or(0);
            if version != 1 {
                return Err(format!("x509: unknown EC private key version {version}"));
            }
            let key = vals[1].as_ref().and_then(Val::as_bytes).unwrap_or_default();
            let curve = match vals[2].as_ref().and_then(Val::as_oid) {
                Some(oid) => curve_from_oid(oid),
                None => None,
            };
            let Some(curve) = curve else {
                return Err("x509: unknown elliptic curve".to_string());
            };
            let n = hex_bytes(curve.n_hex);
            let size = curve.size;
            let mut k = key;
            while k.len() > size {
                if k[0] != 0 {
                    return Err("x509: invalid private key length".to_string());
                }
                k = &k[1..];
            }
            let mut scalar = vec![0u8; size];
            scalar[size - k.len()..].copy_from_slice(k);
            if scalar.iter().all(|&x| x == 0) || bi_cmp(&scalar, &n) != Ordering::Less {
                return Err("ecdsa: invalid public key encoding".to_string());
            }
            Ok(scalar)
        }
        Err(e) => {
            if parse_tlv_struct(der, "pkcs8", PKCS8_FIELDS, 0).is_ok() {
                return Err(
                    "x509: failed to parse private key (use ParsePKCS8PrivateKey instead for this key format)"
                        .to_string(),
                );
            }
            if parse_tlv_struct(der, "pkcs1PrivateKey", PKCS1_PRIV_FIELDS, 0).is_ok() {
                return Err(
                    "x509: failed to parse private key (use ParsePKCS1PrivateKey instead for this key format)"
                        .to_string(),
                );
            }
            Err(format!("x509: failed to parse EC private key: {e}"))
        }
    }
}

// ---------------------------------------------------------------------------
// x509 public key (PKIX)
// ---------------------------------------------------------------------------

pub enum PubKey {
    Ecdsa,
    NotEcdsa,
}

fn read_oid_tlv(params: &[u8]) -> Option<Vec<i64>> {
    let (t, off) = parse_tl(params, 0).ok()?;
    if t.class != 0 || t.tag != 6 || t.compound {
        return None;
    }
    let end = off.checked_add(t.length).filter(|&e| e <= params.len())?;
    parse_oid(&params[off..end]).ok()
}

fn ecdsa_parse_uncompressed(curve: &CurveDef, data: &[u8]) -> Result<(), String> {
    if data.first() != Some(&4) {
        return Err("ecdsa: invalid uncompressed public key".to_string());
    }
    if data.len() != 1 + 2 * curve.size {
        return Err(format!("invalid {} point encoding", curve.name));
    }
    let p = hex_bytes(curve.p_hex);
    let x = &data[1..1 + curve.size];
    let y = &data[1 + curve.size..];
    if bi_cmp(x, &p) != Ordering::Less || bi_cmp(y, &p) != Ordering::Less {
        return Err(format!("invalid {} element encoding", curve.name));
    }
    if curve.name == "P-256" && !p256_on_curve(x, y) {
        return Err("P256 point not on curve".to_string());
    }
    Ok(())
}

fn parse_public_key(oid: &[i64], params: &[u8], data: &[u8]) -> Result<PubKey, String> {
    if oid == RSA_OID {
        if params != [0x05, 0x00] {
            return Err("x509: RSA key missing NULL parameters".to_string());
        }
        let (t, off) = parse_tl(data, 0).map_err(|_| "x509: invalid RSA public key".to_string())?;
        if t.class != 0 || t.tag != 16 || !t.compound {
            return Err("x509: invalid RSA public key".to_string());
        }
        let end = off
            .checked_add(t.length)
            .filter(|&e| e <= data.len())
            .ok_or_else(|| "x509: invalid RSA public key".to_string())?;
        let inner = &data[off..end];
        let (t1, o1) = parse_tl(inner, 0).map_err(|_| "x509: invalid RSA modulus".to_string())?;
        if t1.class != 0 || t1.tag != 2 || t1.compound {
            return Err("x509: invalid RSA modulus".to_string());
        }
        let e1 = o1
            .checked_add(t1.length)
            .filter(|&e| e <= inner.len())
            .ok_or_else(|| "x509: invalid RSA modulus".to_string())?;
        let n = &inner[o1..e1];
        check_integer(n).map_err(|_| "x509: invalid RSA modulus".to_string())?;
        if n.is_empty() {
            return Err("x509: invalid RSA modulus".to_string());
        }
        // two's-complement sign: high bit set means a negative modulus
        if n[0] & 0x80 != 0 {
            return Err("x509: RSA modulus is not a positive number".to_string());
        }
        let (t2, o2) =
            parse_tl(inner, e1).map_err(|_| "x509: invalid RSA public exponent".to_string())?;
        if t2.class != 0 || t2.tag != 2 || t2.compound {
            return Err("x509: invalid RSA public exponent".to_string());
        }
        let e2 = o2
            .checked_add(t2.length)
            .filter(|&e| e <= inner.len())
            .ok_or_else(|| "x509: invalid RSA public exponent".to_string())?;
        let e = parse_int64(&inner[o2..e2])
            .map_err(|_| "x509: invalid RSA public exponent".to_string())?;
        if e <= 0 {
            return Err("x509: RSA public exponent is not a positive number".to_string());
        }
        return Ok(PubKey::NotEcdsa);
    }
    if oid == EC_OID {
        let curve_oid =
            read_oid_tlv(params).ok_or_else(|| "x509: invalid ECDSA parameters".to_string())?;
        let curve = curve_from_oid(&curve_oid)
            .ok_or_else(|| "x509: unsupported elliptic curve".to_string())?;
        ecdsa_parse_uncompressed(curve, data)?;
        return Ok(PubKey::Ecdsa);
    }
    // Ed25519 / X25519 / DSA / unknown: any of them is non-ECDSA; malformed
    // exotic keys still fail later at the caller's ECDSA assertion (same rc).
    Ok(PubKey::NotEcdsa)
}

/// `x509.ParsePKIXPublicKey`.
pub fn parse_pkix_public(der: &[u8]) -> Result<PubKey, String> {
    match parse_tlv_struct(der, "publicKeyInfo", PKIX_FIELDS, 0) {
        Ok((next, vals)) => {
            if next != der.len() {
                return Err("x509: trailing data after ASN.1 of public-key".to_string());
            }
            let alg = vals
                .first()
                .and_then(|v| v.as_ref())
                .and_then(Val::as_list)
                .ok_or_else(|| "asn1: syntax error: sequence truncated".to_string())?;
            let oid = alg
                .first()
                .and_then(|v| v.as_ref())
                .and_then(Val::as_oid)
                .ok_or_else(|| "asn1: syntax error: sequence truncated".to_string())?;
            let params = alg
                .get(1)
                .and_then(|v| v.as_ref())
                .and_then(Val::as_raw)
                .unwrap_or(&[]);
            let data = vals
                .get(1)
                .and_then(|v| v.as_ref())
                .and_then(Val::as_bytes)
                .unwrap_or(&[]);
            parse_public_key(oid, params, data)
        }
        Err(e) => {
            if parse_tlv_struct(der, "pkcs1PublicKey", PKCS1_PUB_FIELDS, 0).is_ok() {
                return Err(
                    "x509: failed to parse public key (use ParsePKCS1PublicKey instead for this key format)"
                        .to_string(),
                );
            }
            Err(e.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn der_wrap(body: &[u8]) -> Vec<u8> {
        let mut out = vec![0x30];
        if body.len() < 128 {
            out.push(body.len() as u8);
        } else {
            out.push(0x81);
            out.push(body.len() as u8);
        }
        out.extend_from_slice(body);
        out
    }

    fn der_seq(fields: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        for f in fields {
            body.extend_from_slice(f);
        }
        der_wrap(&body)
    }

    fn tlv(tag: u8, val: &[u8]) -> Vec<u8> {
        let mut out = vec![tag, val.len() as u8];
        out.extend_from_slice(val);
        out
    }

    const OID256: [u8; 8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

    #[test]
    fn sec1_zero_scalar() {
        let der = der_seq(&[
            tlv(0x02, &[0x01]),
            tlv(0x04, &[0u8; 32]),
            tlv(0xa0, &tlv(0x06, &OID256)),
        ]);
        assert_eq!(
            parse_ec_private(&der).unwrap_err(),
            "ecdsa: invalid public key encoding"
        );
    }

    #[test]
    fn sec1_sequence_truncated() {
        let der = der_wrap(&[0x02, 0x01]);
        let err = parse_ec_private(&der).unwrap_err();
        assert!(
            err.starts_with("x509: failed to parse EC private key: asn1: syntax error:"),
            "got {err}"
        );
    }

    #[test]
    fn pkix_not_ecdsa_for_rsa() {
        // public key: RSA OID with NULL params, pkcs1 {N,E} payload in the bit string
        let n = tlv(0x02, &[0x00, 0xaa, 0xbb]);
        let e = tlv(0x02, &[0x01, 0x00, 0x01]);
        let mut rsa_body = Vec::new();
        rsa_body.extend_from_slice(&n);
        rsa_body.extend_from_slice(&e);
        let rsa_seq = der_wrap(&rsa_body);
        let alg = der_seq(&[
            tlv(
                0x06,
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
            ),
            tlv(0x05, &[]),
        ]);
        let mut bit = vec![0x00];
        bit.extend_from_slice(&rsa_seq);
        let mut pkix_body = alg;
        pkix_body.extend_from_slice(&tlv(0x03, &bit));
        let der = der_wrap(&pkix_body);
        assert!(matches!(parse_pkix_public(&der), Ok(PubKey::NotEcdsa)));
    }
}
