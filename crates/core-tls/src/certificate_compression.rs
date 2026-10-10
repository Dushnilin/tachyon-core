//! Bounded RFC 8879 decoding for the algorithms the browser profiles offer.
use std::io::{self, Read};

use crate::hello::{Ext, Template};

fn bad(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(crate) fn decode(body: &[u8], template: &Template) -> io::Result<Vec<u8>> {
    if body.len() < 8 {
        return Err(bad("short CompressedCertificate"));
    }
    let algorithm = u16::from_be_bytes([body[0], body[1]]);
    let length = |bytes: &[u8]| {
        (usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2])
    };
    let expected = length(&body[2..5]);
    if expected == 0 || expected > 1024 * 1024 || length(&body[5..8]) != body.len() - 8 {
        return Err(bad("invalid CompressedCertificate lengths"));
    }
    let offered = template.extensions.iter().any(|extension| {
        matches!(extension, Ext::Static(27, algorithms)
            if algorithms.get(1..).is_some_and(|list|
                list.as_chunks::<2>().0.iter().any(|pair| *pair == algorithm.to_be_bytes())))
    });
    if !offered {
        return Err(bad(
            "server used an unadvertised certificate compression algorithm",
        ));
    }
    let compressed = &body[8..];
    let reader: Box<dyn Read + '_> = match algorithm {
        1 => Box::new(flate2::read::ZlibDecoder::new(compressed)),
        2 => Box::new(brotli::Decompressor::new(compressed, 4096)),
        3 => Box::new(
            ruzstd::decoding::StreamingDecoder::new(compressed)
                .map_err(|_| bad("invalid zstd certificate frame"))?,
        ),
        _ => return Err(bad("unsupported certificate compression algorithm")),
    };
    let mut decoded = Vec::with_capacity(expected);
    reader.take(expected as u64 + 1).read_to_end(&mut decoded)?;
    if decoded.len() != expected {
        return Err(bad("certificate decompressed length mismatch"));
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn refuses_bad_lengths_unoffered_algorithms_and_excess_output() {
        let template = crate::fingerprints::firefox();
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&[7; 64]).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut body = vec![0, 1, 0, 0, 64];
        let length = u32::try_from(compressed.len()).unwrap().to_be_bytes();
        body.extend_from_slice(&length[1..]);
        body.extend_from_slice(&compressed);
        assert_eq!(decode(&body, &template).unwrap(), vec![7; 64]);
        body[4] = 63;
        assert!(decode(&body, &template).is_err());
        body[4] = 65;
        assert!(decode(&body, &template).is_err());
        body[4] = 64;
        body[1] = 99;
        assert!(decode(&body, &template).is_err());
        assert!(decode(&[0; 7], &template).is_err());
        body[2] = 0xff;
        assert!(decode(&body, &template).is_err());
    }
}
