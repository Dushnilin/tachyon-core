//! Minimal zip reader for the Clash API's `external_ui` bundle.
//!
//! Enough for what a dashboard archive is: a central directory, `stored` and
//! `deflate` entries, one shared top-level directory trimmed on the way out.
//! Zip64, encrypted and multi-disk archives are refused rather than guessed
//! at, entry paths are validated before anything is written, and the CRC is
//! not checked — the reference does not check it either.

use std::io::{self, Read};
use std::path::{Component, Path};

const LOCAL_SIG: u32 = 0x0403_4b50;
const CENTRAL_SIG: u32 = 0x0201_4b50;
const EOCD_SIG: u32 = 0x0605_4b50;
/// End of central directory: fixed size plus the largest zip comment.
const EOCD_SIZE: usize = 22;
const EOCD_SCAN: usize = EOCD_SIZE + u16::MAX as usize;
const METHOD_STORED: u16 = 0;
const METHOD_DEFLATE: u16 = 8;

struct Entry {
    /// Central-directory name, `/` separated, possibly with a trailing slash.
    path: String,
    method: u16,
    compressed: usize,
    /// Where this entry's payload starts in the archive.
    data_offset: usize,
}

fn slice(bytes: &[u8], at: usize, len: usize) -> io::Result<&[u8]> {
    let end = at
        .checked_add(len)
        .ok_or_else(|| io::Error::other("zip: offset overflow"))?;
    bytes
        .get(at..end)
        .ok_or_else(|| io::Error::other("zip: truncated archive"))
}

fn u16_at(bytes: &[u8], at: usize) -> io::Result<u16> {
    Ok(u16::from_le_bytes(
        slice(bytes, at, 2)?.try_into().expect("two bytes"),
    ))
}

fn u32_at(bytes: &[u8], at: usize) -> io::Result<u32> {
    Ok(u32::from_le_bytes(
        slice(bytes, at, 4)?.try_into().expect("four bytes"),
    ))
}

/// Position of the end-of-central-directory record, scanning backwards over
/// the comment the way every zip reader has to.
fn find_eocd(bytes: &[u8]) -> io::Result<usize> {
    if bytes.len() < EOCD_SIZE {
        return Err(io::Error::other("zip: truncated archive"));
    }
    let first = bytes.len() - EOCD_SCAN.min(bytes.len());
    let mut at = bytes.len() - EOCD_SIZE;
    loop {
        if u32_at(bytes, at)? == EOCD_SIG
            && u16_at(bytes, at + 20)? as usize == bytes.len() - at - EOCD_SIZE
        {
            return Ok(at);
        }
        if at == first {
            break;
        }
        at -= 1;
    }
    Err(io::Error::other("zip: no end of central directory record"))
}

/// Read the central directory and locate every entry's payload.
fn entries(bytes: &[u8]) -> io::Result<Vec<Entry>> {
    let eocd = find_eocd(bytes)?;
    let count = u16_at(bytes, eocd + 8)?;
    let offset_raw = u32_at(bytes, eocd + 16)?;
    if count == u16::MAX || offset_raw == u32::MAX {
        return Err(io::Error::other("zip: zip64 is not supported"));
    }
    let mut entries = Vec::with_capacity(count as usize);
    let mut at = offset_raw as usize;
    for _ in 0..count {
        if u32_at(bytes, at)? != CENTRAL_SIG {
            return Err(io::Error::other("zip: bad central directory entry"));
        }
        let method = u16_at(bytes, at + 10)?;
        let compressed = u32_at(bytes, at + 20)? as usize;
        let name_len = u16_at(bytes, at + 28)? as usize;
        let extra_len = u16_at(bytes, at + 30)? as usize;
        let comment_len = u16_at(bytes, at + 32)? as usize;
        let local = u32_at(bytes, at + 42)? as usize;
        let name = String::from_utf8_lossy(slice(bytes, at + 46, name_len)?).into_owned();

        if u32_at(bytes, local)? != LOCAL_SIG {
            return Err(io::Error::other(format!("zip: {name}: bad local header")));
        }
        let local_name_len = u16_at(bytes, local + 26)? as usize;
        let local_extra_len = u16_at(bytes, local + 28)? as usize;
        let data_offset = local + 30 + local_name_len + local_extra_len;

        entries.push(Entry {
            path: name,
            method,
            compressed,
            data_offset,
        });
        at = at
            .checked_add(46 + name_len + extra_len + comment_len)
            .ok_or_else(|| io::Error::other("zip: offset overflow"))?;
    }
    Ok(entries)
}

/// The reference drops one shared top-level directory — a dashboard bundle
/// unpacks as `Yacd-meta-gh-pages/...`. Archives without one are left alone.
fn single_top_directory(entries: &[Entry]) -> bool {
    let mut top: Option<&str> = None;
    for entry in entries {
        if entry.path.ends_with('/') {
            continue;
        }
        let Some((first, rest)) = entry.path.split_once('/') else {
            return false;
        };
        if rest.is_empty() {
            return false;
        }
        match top {
            None => top = Some(first),
            Some(known) if known == first => {}
            Some(_) => return false,
        }
    }
    top.is_some()
}

/// Unpack `bytes` into `dest`, creating the directory when it is missing.
pub fn extract(bytes: &[u8], dest: &Path) -> io::Result<()> {
    let entries = entries(bytes)?;
    let trim = single_top_directory(&entries);
    std::fs::create_dir_all(dest)?;
    for entry in &entries {
        let mut parts: Vec<&str> = entry.path.split('/').collect();
        if trim {
            parts.remove(0);
        }
        // a trailing slash is what marks a directory entry
        let is_dir = entry.path.ends_with('/');
        parts.retain(|part| !part.is_empty());
        if parts.is_empty() {
            continue;
        }
        let mut path = dest.to_path_buf();
        for part in parts {
            // zip-slip: `..`, an absolute root or a drive prefix never leaves
            // the destination directory
            match Path::new(part).components().next() {
                Some(Component::Normal(name)) if !name.to_string_lossy().contains('\\') => {
                    path.push(name)
                }
                _ => {
                    return Err(io::Error::other(format!(
                        "zip: unsafe entry path {:?}",
                        entry.path
                    )));
                }
            }
        }
        if is_dir {
            std::fs::create_dir_all(&path)?;
            continue;
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, payload(bytes, entry)?)?;
    }
    Ok(())
}

fn payload(bytes: &[u8], entry: &Entry) -> io::Result<Vec<u8>> {
    let stored = slice(bytes, entry.data_offset, entry.compressed)?;
    match entry.method {
        METHOD_STORED => Ok(stored.to_vec()),
        METHOD_DEFLATE => {
            let mut out = Vec::new();
            flate2::read::DeflateDecoder::new(stored).read_to_end(&mut out)?;
            Ok(out)
        }
        other => Err(io::Error::other(format!(
            "zip: unsupported compression method {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    struct TestEntry {
        name: &'static str,
        data: Vec<u8>,
        deflate: bool,
    }

    /// A hand-rolled archive: local headers, one central directory, EOCD.
    fn build(entries: &[TestEntry]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for entry in entries {
            let offset = out.len() as u32;
            let (method, payload) = if entry.deflate {
                let mut encoder =
                    flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(&entry.data).expect("deflate");
                (METHOD_DEFLATE, encoder.finish().expect("deflate"))
            } else {
                (METHOD_STORED, entry.data.to_vec())
            };
            out.extend_from_slice(&LOCAL_SIG.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // version
            out.extend_from_slice(&0u16.to_le_bytes()); // flags
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // time
            out.extend_from_slice(&0u16.to_le_bytes()); // date
            out.extend_from_slice(&0u32.to_le_bytes()); // crc (not checked)
            out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            out.extend_from_slice(&(entry.data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(entry.name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // extra
            out.extend_from_slice(entry.name.as_bytes());
            out.extend_from_slice(&payload);

            central.extend_from_slice(&CENTRAL_SIG.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes()); // version made by
            central.extend_from_slice(&0u16.to_le_bytes()); // version needed
            central.extend_from_slice(&0u16.to_le_bytes()); // flags
            central.extend_from_slice(&method.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes()); // time
            central.extend_from_slice(&0u16.to_le_bytes()); // date
            central.extend_from_slice(&0u32.to_le_bytes()); // crc
            central.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            central.extend_from_slice(&(entry.data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(entry.name.len() as u16).to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes()); // extra
            central.extend_from_slice(&0u16.to_le_bytes()); // comment
            central.extend_from_slice(&0u16.to_le_bytes()); // disk
            central.extend_from_slice(&0u16.to_le_bytes()); // internal
            central.extend_from_slice(&0u32.to_le_bytes()); // external
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(entry.name.as_bytes());
        }
        let central_offset = out.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(&EOCD_SIG.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // disk
        out.extend_from_slice(&0u16.to_le_bytes()); // central disk
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(central.len() as u32).to_le_bytes());
        out.extend_from_slice(&central_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // comment length
        out
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("tachyon-zip-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn a_bundle_unpacks_with_its_top_directory_trimmed() {
        let html = b"<!doctype html><html></html>".to_vec();
        let js = b"export const answer = 42;\n".repeat(64);
        let archive = build(&[
            TestEntry {
                name: "Yacd-meta-gh-pages/index.html",
                data: html.clone(),
                deflate: false,
            },
            TestEntry {
                name: "Yacd-meta-gh-pages/static/js/app.js",
                data: js.clone(),
                deflate: true,
            },
            TestEntry {
                name: "Yacd-meta-gh-pages/static/",
                data: Vec::new(),
                deflate: false,
            },
        ]);
        let dest = scratch("bundle");
        extract(&archive, &dest).expect("extract");

        assert_eq!(
            std::fs::read(dest.join("index.html")).expect("index.html"),
            html
        );
        assert_eq!(
            std::fs::read(dest.join("static/js/app.js")).expect("app.js"),
            js
        );
        assert!(dest.join("static").is_dir());
        assert!(
            !dest.join("Yacd-meta-gh-pages").exists(),
            "the shared top directory is trimmed"
        );
        let _ = std::fs::remove_dir_all(&dest);
    }

    #[test]
    fn a_flat_archive_keeps_every_name() {
        let archive = build(&[TestEntry {
            name: "index.html",
            data: b"root".to_vec(),
            deflate: false,
        }]);
        let dest = scratch("flat");
        extract(&archive, &dest).expect("extract");
        assert_eq!(
            std::fs::read(dest.join("index.html")).expect("file"),
            b"root"
        );
        let _ = std::fs::remove_dir_all(&dest);
    }

    #[test]
    fn a_zip_slip_entry_is_refused() {
        let archive = build(&[TestEntry {
            name: "bundle/../../escape.txt",
            data: b"nope".to_vec(),
            deflate: false,
        }]);
        let dest = scratch("slip");
        let err = extract(&archive, &dest).expect_err("must refuse");
        assert!(err.to_string().contains("unsafe entry path"), "{err}");
        assert!(!dest.join("escape.txt").exists());
        let _ = std::fs::remove_dir_all(&dest);
    }

    #[test]
    fn truncated_and_zip64_archives_are_refused() {
        let archive = build(&[TestEntry {
            name: "bundle/index.html",
            data: b"x".to_vec(),
            deflate: false,
        }]);
        let err =
            extract(&archive[..archive.len() - 10], &scratch("short")).expect_err("truncated");
        assert!(err.to_string().contains("zip:"), "{err}");

        let mut zip64 = archive.clone();
        let eocd = find_eocd(&zip64).expect("eocd");
        zip64[eocd + 8..eocd + 10].copy_from_slice(&u16::MAX.to_le_bytes());
        let err = extract(&zip64, &scratch("zip64")).expect_err("zip64");
        assert!(err.to_string().contains("zip64"), "{err}");
    }

    #[test]
    fn garbage_is_refused_without_panicking() {
        let junk: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        assert!(extract(&junk, &scratch("junk")).is_err());
        assert!(extract(&[], &scratch("empty")).is_err());
        let _ = std::fs::remove_dir_all(scratch("junk"));
        let _ = std::fs::remove_dir_all(scratch("empty"));
    }
}
