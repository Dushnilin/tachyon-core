//! Minimal secp256r1 (P-256) arithmetic: derive the client-certificate public
//! key from a configured SEC 1 private scalar.
//!
//! The MASQUE feature may not add dependencies (`p256` is not a workspace
//! dependency), so scalar multiplication is implemented here in plain Rust:
//! Jacobian point operations with a constant-time conditional-swap ladder and
//! bit-serial field reduction. Cost is fine — a client certificate is
//! generated once per dial.
//!
//! Verified against RFC 6979 A.2.5 and the repository's golden certificate.

use core::cmp::Ordering;

type Fe = [u64; 4];
type Wide = [u64; 8];

/// Field prime p = 2^256 - 2^224 + 2^192 + 2^96 - 1.
const P: Fe = [
    0xFFFFFFFFFFFFFFFF,
    0x00000000FFFFFFFF,
    0x0000000000000000,
    0xFFFFFFFF00000001,
];

/// Group order n.
const N: Fe = [
    0xF3B9CAC2FC632551,
    0xBCE6FAADA7179E84,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFF00000000,
];

/// Curve coefficient b (a = -3 is baked into the doubling formulas).
const B: Fe = [
    0x3BCE3C3E27D2604B,
    0x651D06B0CC53B0F6,
    0xB3EBBD55769886BC,
    0x5AC635D8AA3A93E7,
];

const GX: Fe = [
    0xF4A13945D898C296,
    0x77037D812DEB33A0,
    0xF8BCE6E563A440F2,
    0x6B17D1F2E12C4247,
];

const GY: Fe = [
    0xCBB6406837BF51F5,
    0x2BCE33576B315ECE,
    0x8EE7EB4A7C0F9E16,
    0x4FE342E2FE1A7F9B,
];

const ONE: Fe = [1, 0, 0, 0];
const ZERO: Fe = [0; 4];

const INF: Point = Point {
    x: ZERO,
    y: ZERO,
    z: ZERO,
};

const G_JACOBIAN: Point = Point {
    x: GX,
    y: GY,
    z: ONE,
};

#[derive(Clone, Copy, PartialEq, Eq)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    ZeroScalar,
    ScalarOutOfRange,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::ZeroScalar => write!(f, "masque: private key scalar is zero"),
            Error::ScalarOutOfRange => write!(f, "masque: private key scalar out of range"),
        }
    }
}

impl std::error::Error for Error {}

fn from_be(b: &[u8]) -> Fe {
    debug_assert_eq!(b.len(), 32);
    let mut fe = [0u64; 4];
    for (i, limb) in fe.iter_mut().rev().enumerate() {
        *limb = u64::from_be_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
    }
    fe
}

fn to_be(fe: &Fe) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, limb) in fe.iter().rev().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&limb.to_be_bytes());
    }
    out
}

fn cmp(a: &Fe, b: &Fe) -> Ordering {
    for i in (0..4).rev() {
        match a[i].cmp(&b[i]) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    Ordering::Equal
}

fn add(a: &Fe, b: &Fe) -> (Fe, u64) {
    let mut out = [0u64; 4];
    let mut carry = 0u64;
    for i in 0..4 {
        let (s1, c1) = a[i].overflowing_add(b[i]);
        let (s2, c2) = s1.overflowing_add(carry);
        out[i] = s2;
        carry = u64::from(c1) + u64::from(c2);
    }
    (out, carry)
}

fn sub(a: &Fe, b: &Fe) -> (Fe, u64) {
    let mut out = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        out[i] = d2;
        borrow = u64::from(b1) + u64::from(b2);
    }
    (out, borrow)
}

fn mul(a: &Fe, b: &Fe) -> Wide {
    let mut out = [0u64; 8];
    for (i, &ai) in a.iter().enumerate() {
        let mut carry = 0u128;
        for (j, &bj) in b.iter().enumerate() {
            let idx = i + j;
            let cur = u128::from(out[idx]) + u128::from(ai) * u128::from(bj) + carry;
            out[idx] = cur as u64;
            carry = cur >> 64;
        }
        let mut idx = i + 4;
        while carry > 0 && idx < 8 {
            let cur = u128::from(out[idx]) + carry;
            out[idx] = cur as u64;
            carry = cur >> 64;
            idx += 1;
        }
        debug_assert_eq!(carry, 0);
    }
    out
}

/// Reduce a 512-bit product modulo p by bit-serial conditional subtraction.
fn mod_p(w: &Wide) -> Fe {
    let mut rem = [0u64; 5];
    for i in (0..8).rev() {
        for bit in (0..64).rev() {
            let inject = (w[i] >> bit) & 1;
            let mut carry = inject;
            for limb in rem.iter_mut() {
                let top = *limb >> 63;
                *limb = (*limb << 1) | carry;
                carry = top;
            }
            if rem_ge_p(&rem) {
                sub_p(&mut rem);
            }
        }
    }
    [rem[0], rem[1], rem[2], rem[3]]
}

fn rem_ge_p(rem: &[u64; 5]) -> bool {
    if rem[4] != 0 {
        return true;
    }
    cmp(&[rem[0], rem[1], rem[2], rem[3]], &P) != Ordering::Less
}

/// Subtract p (as a 5-limb value with a zero high limb); the caller has
/// established `rem >= p` and `rem < 2p`, so the high limb returns to zero.
fn sub_p(rem: &mut [u64; 5]) {
    let mut p5 = [0u64; 5];
    p5[..4].copy_from_slice(&P);
    let mut borrow = 0u64;
    for i in 0..5 {
        let (d1, b1) = rem[i].overflowing_sub(p5[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        rem[i] = d2;
        borrow = u64::from(b1) + u64::from(b2);
    }
    debug_assert_eq!(borrow, 0);
    debug_assert_eq!(rem[4], 0);
}

fn add_mod_p(a: &Fe, b: &Fe) -> Fe {
    let (sum, carry) = add(a, b);
    if carry == 0 && cmp(&sum, &P) == Ordering::Less {
        return sum;
    }
    let mut rem = [0u64; 5];
    rem[..4].copy_from_slice(&sum);
    rem[4] = carry;
    sub_p(&mut rem);
    [rem[0], rem[1], rem[2], rem[3]]
}

fn sub_mod_p(a: &Fe, b: &Fe) -> Fe {
    let (d, borrow) = sub(a, b);
    if borrow != 0 {
        let (d2, _) = add(&d, &P);
        d2
    } else {
        d
    }
}

fn mul_mod_p(a: &Fe, b: &Fe) -> Fe {
    mod_p(&mul(a, b))
}

fn square_mod_p(a: &Fe) -> Fe {
    mul_mod_p(a, a)
}

fn double_fe(a: &Fe) -> Fe {
    add_mod_p(a, a)
}

/// a^(p-2) mod p — Fermat inversion.
fn inv(a: &Fe) -> Fe {
    // p - 2
    let exp: Fe = [
        0xFFFFFFFFFFFFFFFD,
        0x00000000FFFFFFFF,
        0x0000000000000000,
        0xFFFFFFFF00000001,
    ];
    let mut result = ONE;
    for limb in exp.iter().rev() {
        for bit in (0..64).rev() {
            result = square_mod_p(&result);
            if (limb >> bit) & 1 == 1 {
                result = mul_mod_p(&result, a);
            }
        }
    }
    result
}

fn is_zero(a: &Fe) -> bool {
    *a == ZERO
}

fn ct_select(a: &Point, b: &Point, pick_b: bool) -> Point {
    let mask = if pick_b { u64::MAX } else { 0 };
    let sel = |x: &Fe, y: Fe| -> Fe {
        let mut out = [0u64; 4];
        for i in 0..4 {
            out[i] = (x[i] & !mask) | (y[i] & mask);
        }
        out
    };
    Point {
        x: sel(&a.x, b.x),
        y: sel(&a.y, b.y),
        z: sel(&a.z, b.z),
    }
}

/// Jacobian point doubling for a = -3 (dbl-2009-l).
fn j_double(p: &Point) -> Point {
    if is_zero(&p.z) || is_zero(&p.y) {
        return INF;
    }
    let delta = square_mod_p(&p.z);
    let gamma = square_mod_p(&p.y);
    let beta = mul_mod_p(&p.x, &gamma);
    let t = mul_mod_p(&sub_mod_p(&p.x, &delta), &add_mod_p(&p.x, &delta));
    let alpha = add_mod_p(&double_fe(&t), &t); // 3 * (x - z^2)(x + z^2)
    let x3 = sub_mod_p(
        &square_mod_p(&alpha),
        &double_fe(&double_fe(&double_fe(&beta))),
    );
    let four_beta = double_fe(&double_fe(&beta));
    let y3 = sub_mod_p(
        &mul_mod_p(&alpha, &sub_mod_p(&four_beta, &x3)),
        &double_fe(&double_fe(&double_fe(&square_mod_p(&gamma)))),
    );
    let z3 = sub_mod_p(
        &sub_mod_p(&square_mod_p(&add_mod_p(&p.y, &p.z)), &gamma),
        &delta,
    );
    Point {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// Jacobian point addition (add-2007-bl).
fn j_add(p1: &Point, p2: &Point) -> Point {
    if is_zero(&p1.z) {
        return *p2;
    }
    if is_zero(&p2.z) {
        return *p1;
    }
    let z1z1 = square_mod_p(&p1.z);
    let z2z2 = square_mod_p(&p2.z);
    let u1 = mul_mod_p(&p1.x, &z2z2);
    let u2 = mul_mod_p(&p2.x, &z1z1);
    let s1 = mul_mod_p(&mul_mod_p(&p1.y, &p2.z), &z2z2);
    let s2 = mul_mod_p(&mul_mod_p(&p2.y, &p1.z), &z1z1);
    let h = sub_mod_p(&u2, &u1);
    let r = double_fe(&sub_mod_p(&s2, &s1));
    if is_zero(&h) {
        return if is_zero(&r) { j_double(p1) } else { INF };
    }
    let i = square_mod_p(&double_fe(&h));
    let j = mul_mod_p(&h, &i);
    let v = mul_mod_p(&u1, &i);
    let x3 = sub_mod_p(&sub_mod_p(&square_mod_p(&r), &j), &double_fe(&v));
    let y3 = sub_mod_p(
        &mul_mod_p(&r, &sub_mod_p(&v, &x3)),
        &double_fe(&mul_mod_p(&s1, &j)),
    );
    let z3 = mul_mod_p(
        &sub_mod_p(
            &sub_mod_p(&square_mod_p(&add_mod_p(&p1.z, &p2.z)), &z1z1),
            &z2z2,
        ),
        &h,
    );
    Point {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// Constant-time scalar multiplication `k * G` (k as 32 big-endian bytes).
fn scalar_mult(k: &[u8; 32]) -> Point {
    let mut r = INF;
    for byte in k {
        for bit in (0..8).rev() {
            let dbl = j_double(&r);
            let sum = j_add(&dbl, &G_JACOBIAN);
            r = ct_select(&dbl, &sum, (byte >> bit) & 1 == 1);
        }
    }
    r
}

fn to_affine(p: &Point) -> Option<(Fe, Fe)> {
    if is_zero(&p.z) {
        return None;
    }
    let zinv = inv(&p.z);
    let zinv2 = square_mod_p(&zinv);
    let zinv3 = mul_mod_p(&zinv2, &zinv);
    Some((mul_mod_p(&p.x, &zinv2), mul_mod_p(&p.y, &zinv3)))
}

/// Derive the uncompressed public key point `04 || X || Y` for a P-256 private
/// scalar (big-endian, 32 bytes; shorter inputs are left-padded).
pub(crate) fn derive_public_key(scalar: &[u8]) -> Result<Vec<u8>, Error> {
    if scalar.len() > 32 && scalar[..scalar.len() - 32].iter().any(|&b| b != 0) {
        return Err(Error::ScalarOutOfRange);
    }
    let mut k = [0u8; 32];
    let tail = &scalar[scalar.len().saturating_sub(32)..];
    k[32 - tail.len()..].copy_from_slice(tail);
    if k == [0u8; 32] {
        return Err(Error::ZeroScalar);
    }
    if cmp(&from_be(&k), &N) != Ordering::Less {
        return Err(Error::ScalarOutOfRange);
    }
    let point = scalar_mult(&k);
    let (x, y) = to_affine(&point).ok_or(Error::ZeroScalar)?;
    let mut out = Vec::with_capacity(65);
    out.push(0x04);
    out.extend_from_slice(&to_be(&x));
    out.extend_from_slice(&to_be(&y));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex_fe(fe: &Fe) -> String {
        fe.iter().rev().map(|l| format!("{l:016x}")).collect()
    }

    #[test]
    fn double_add_scalarmult_known_answer() {
        // Field layer known answers (python pow reference).
        assert_eq!(
            hex_fe(&mul_mod_p(&GX, &GX)),
            "98f6b84d29bef2b281819a5e0e3690d833b699495d694dd1002ae56c426b3f8c"
        );
        assert_eq!(
            hex_fe(&inv(&GY)),
            "fa27a3da2c00618a828f8cd65c1a919effc67bf68b4dbb05bbdaa775c45d4034"
        );
        assert_eq!(mul_mod_p(&GY, &inv(&GY)), ONE);
        let d = j_double(&G_JACOBIAN);
        let da = to_affine(&d).expect("dbl affine");
        let a = j_add(&G_JACOBIAN, &G_JACOBIAN);
        let aa = to_affine(&a).expect("add affine");
        let m2 = scalar_mult(&{
            let mut k = [0u8; 32];
            k[31] = 2;
            k
        });
        let m2a = to_affine(&m2).expect("m2 affine");
        let want = (
            "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
            "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1",
        );
        assert_eq!(hex_fe(&da.0), want.0, "dbl x");
        assert_eq!(hex_fe(&da.1), want.1, "dbl y");
        assert_eq!(hex_fe(&aa.0), want.0, "add x");
        assert_eq!(hex_fe(&aa.1), want.1, "add y");
        assert_eq!(hex_fe(&m2a.0), want.0, "m2 x");
        assert_eq!(hex_fe(&m2a.1), want.1, "m2 y");
    }

    #[test]
    fn rfc6979_p256_known_answer() {
        // RFC 6979 A.2.5 P-256 (SHA-256): private key / public key pair.
        let k = hex_decode("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
        let want_x = hex_decode("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6");
        let want_y = hex_decode("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299");
        let q = derive_public_key(&k).unwrap();
        assert_eq!(q.len(), 65);
        assert_eq!(q[0], 0x04);
        assert_eq!(&q[1..33], &want_x[..]);
        assert_eq!(&q[33..], &want_y[..]);
    }

    #[test]
    fn generator_scalar_one() {
        let mut k = [0u8; 32];
        k[31] = 1;
        let q = derive_public_key(&k).unwrap();
        assert_eq!(&q[1..33], &to_be(&GX));
        assert_eq!(&q[33..], &to_be(&GY));
    }

    #[test]
    fn point_satisfies_curve_equation() {
        // y^2 == x^3 - 3x + b (mod p) for the RFC 6979 derived point.
        let k = hex_decode("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
        let q = derive_public_key(&k).unwrap();
        let x = from_be(&q[1..33]);
        let y = from_be(&q[33..]);
        let lhs = square_mod_p(&y);
        let x3 = mul_mod_p(&square_mod_p(&x), &x);
        let three_x = add_mod_p(&double_fe(&x), &x);
        let rhs = add_mod_p(&sub_mod_p(&x3, &three_x), &B);
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn rejects_zero_and_out_of_range_scalar() {
        assert_eq!(derive_public_key(&[0u8; 32]), Err(Error::ZeroScalar));
        assert_eq!(derive_public_key(&[0xff; 32]), Err(Error::ScalarOutOfRange));
        // Left-padding a short scalar works.
        let mut short = vec![0u8; 31];
        short[30] = 2;
        let q = derive_public_key(&short).unwrap();
        assert_eq!(q[0], 0x04);
        let mut two = [0u8; 32];
        two[31] = 2;
        assert_eq!(q, derive_public_key(&two).unwrap());
    }

    #[test]
    fn golden_key_derives_golden_cert_point() {
        let key = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/golden/certs/localhost.key"
        ))
        .expect("golden key");
        let cert = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/golden/certs/localhost.crt"
        ))
        .expect("golden cert");
        let der = pem_body(&key);
        let scalar = sec1_scalar(&der).expect("sec1 scalar");
        let q = derive_public_key(&scalar).expect("derive");
        let spki_point = cert_spki_point(&pem_body(&cert)).expect("spki");
        assert_eq!(&q[..], &spki_point[..]);
    }

    fn pem_body(pem: &str) -> Vec<u8> {
        let b64: String = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .map(str::trim)
            .collect();
        base64_decode(&b64)
    }

    fn base64_decode(s: &str) -> Vec<u8> {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut vals = Vec::new();
        for c in s.bytes() {
            if c == b'=' {
                break;
            }
            if let Some(v) = TABLE.iter().position(|&t| t == c) {
                vals.push(v as u8);
            }
        }
        let mut out = Vec::new();
        for chunk in vals.chunks(4) {
            let mut acc = 0u32;
            for (i, v) in chunk.iter().enumerate() {
                acc |= u32::from(*v) << (18 - 6 * i);
            }
            for i in 0..chunk.len().saturating_sub(1) {
                out.push(((acc >> (16 - 8 * i)) & 0xff) as u8);
            }
        }
        out
    }

    fn tlv(buf: &[u8], at: usize) -> Result<(u8, &'_ [u8], usize), ()> {
        let tag = *buf.get(at).ok_or(())?;
        let mut pos = at + 1;
        let first = *buf.get(pos).ok_or(())?;
        pos += 1;
        let len = if first & 0x80 == 0 {
            usize::from(first)
        } else {
            let n = usize::from(first & 0x7f);
            if n == 0 || n > 4 {
                return Err(());
            }
            let mut v = 0usize;
            for _ in 0..n {
                v = (v << 8) | usize::from(*buf.get(pos).ok_or(())?);
                pos += 1;
            }
            v
        };
        let end = pos + len;
        if end > buf.len() {
            return Err(());
        }
        Ok((tag, &buf[pos..end], end))
    }

    /// SEC 1 `ECPrivateKey` TLV walk: SEQUENCE { INTEGER, OCTET STRING, ... }.
    /// PKCS#8 (`BEGIN PRIVATE KEY`) is unwrapped first: SEQUENCE { INTEGER,
    /// SEQ AlgorithmIdentifier, OCTET STRING (SEC 1 ECPrivateKey) }.
    fn sec1_scalar(der: &[u8]) -> Result<Vec<u8>, ()> {
        let (tag, content, _) = tlv(der, 0)?;
        if tag != 0x30 {
            return Err(());
        }
        let (t1, _, n1) = tlv(content, 0)?;
        if t1 != 0x02 {
            return Err(());
        }
        let (t2, c2, n2) = tlv(content, n1)?;
        if t2 == 0x04 {
            return Ok(c2.to_vec());
        }
        if t2 == 0x30 {
            let (t3, c3, _) = tlv(content, n2)?;
            if t3 == 0x04 {
                return sec1_scalar(c3);
            }
        }
        Err(())
    }

    /// Extract the raw EC point (04||X||Y) from a certificate's SPKI.
    fn cert_spki_point(cert_der: &[u8]) -> Result<Vec<u8>, ()> {
        let (t, cert, _) = tlv(cert_der, 0)?;
        if t != 0x30 {
            return Err(());
        }
        let (t, tbs, _) = tlv(cert, 0)?;
        if t != 0x30 {
            return Err(());
        }
        let mut pos = 0;
        let (tag0, _, n0) = tlv(tbs, pos)?;
        if tag0 == 0xa0 {
            pos = n0;
        }
        let mut spki = None;
        for idx in 0..6 {
            let (tag, _, n) = tlv(tbs, pos)?;
            if idx == 5 && tag == 0x30 {
                spki = Some(&tbs[pos..n]);
            }
            pos = n;
        }
        let spki = spki.ok_or(())?;
        let (t, spki_content, _) = tlv(spki, 0)?;
        if t != 0x30 {
            return Err(());
        }
        let (_, _, n_alg) = tlv(spki_content, 0)?;
        let (t, bit, _) = tlv(spki_content, n_alg)?;
        if t != 0x03 || bit.first() != Some(&0) {
            return Err(());
        }
        Ok(bit[1..].to_vec())
    }
}
