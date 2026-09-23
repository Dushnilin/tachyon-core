use std::fs;
use std::io;
use std::path::Path;

pub const MAGIC: u32 = 0xED0CDAED;
pub const VERSION: u32 = 2;
const NO_FREELIST: u64 = u64::MAX;
const META_FLAG: u16 = 0x04;
const BRANCH_FLAG: u16 = 0x01;
const LEAF_FLAG: u16 = 0x02;
const BUCKET_LEAF_FLAG: u32 = 0x01;
const PAGE_HEADER: usize = 16;
const META_BODY: usize = 64;
const LEAF_ELEM: usize = 16;
const BRANCH_ELEM: usize = 16;
const BUCKET_HEADER: usize = 16;

fn err(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn fnv1a64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn u16(&self, off: usize) -> io::Result<u16> {
        let b = self.buf.get(off..off + 2).ok_or_else(|| err("u16 oob"))?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&self, off: usize) -> io::Result<u32> {
        let b = self.buf.get(off..off + 4).ok_or_else(|| err("u32 oob"))?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&self, off: usize) -> io::Result<u64> {
        let b = self.buf.get(off..off + 8).ok_or_else(|| err("u64 oob"))?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }

    fn bytes(&self, off: usize, len: usize) -> io::Result<&'a [u8]> {
        self.buf.get(off..off + len).ok_or_else(|| err("bytes oob"))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Meta {
    pub page_size: u32,
    pub root: u64,
    pub sequence: u64,
    pub freelist: u64,
    pub pgid: u64,
    pub txid: u64,
}

fn parse_meta(page_prefix: &[u8]) -> Option<Meta> {
    let r = Reader { buf: page_prefix };
    if r.u32(PAGE_HEADER).ok()? != MAGIC || r.u32(PAGE_HEADER + 4).ok()? != VERSION {
        return None;
    }
    let stored = r.u64(PAGE_HEADER + 56).ok()?;
    if fnv1a64(page_prefix.get(PAGE_HEADER..PAGE_HEADER + 56)?) != stored {
        return None;
    }
    Some(Meta {
        page_size: r.u32(PAGE_HEADER + 8).ok()?,
        root: r.u64(PAGE_HEADER + 16).ok()?,
        sequence: r.u64(PAGE_HEADER + 24).ok()?,
        freelist: r.u64(PAGE_HEADER + 32).ok()?,
        pgid: r.u64(PAGE_HEADER + 40).ok()?,
        txid: r.u64(PAGE_HEADER + 48).ok()?,
    })
}

enum PageKind {
    Leaf,
    Branch,
}

struct Elem {
    flags: u32,
    key: Vec<u8>,
    value: Vec<u8>,
    child: u64,
}

fn page_kind(page: &[u8]) -> io::Result<PageKind> {
    match (Reader { buf: page }).u16(8)? {
        LEAF_FLAG => Ok(PageKind::Leaf),
        BRANCH_FLAG => Ok(PageKind::Branch),
        _ => Err(err("unexpected page type")),
    }
}

fn leaf_elems(page: &[u8]) -> io::Result<Vec<Elem>> {
    let r = Reader { buf: page };
    let count = r.u16(10)? as usize;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let e = PAGE_HEADER + i * LEAF_ELEM;
        let flags = r.u32(e)?;
        let pos = r.u32(e + 4)? as usize;
        let ksize = r.u32(e + 8)? as usize;
        let vsize = r.u32(e + 12)? as usize;
        let data = e + pos;
        out.push(Elem {
            flags,
            key: r.bytes(data, ksize)?.to_vec(),
            value: r.bytes(data + ksize, vsize)?.to_vec(),
            child: 0,
        });
    }
    Ok(out)
}

fn branch_elems(page: &[u8]) -> io::Result<Vec<Elem>> {
    let r = Reader { buf: page };
    let count = r.u16(10)? as usize;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let e = PAGE_HEADER + i * BRANCH_ELEM;
        let pos = r.u32(e)? as usize;
        let ksize = r.u32(e + 4)? as usize;
        let pgid = r.u64(e + 8)?;
        let data = e + pos;
        out.push(Elem {
            flags: 0,
            key: r.bytes(data, ksize)?.to_vec(),
            value: Vec::new(),
            child: pgid,
        });
    }
    Ok(out)
}

pub struct Db {
    data: Vec<u8>,
    page_size: usize,
    meta: Meta,
}

impl Db {
    pub fn open(path: &Path) -> io::Result<Db> {
        let data = fs::read(path)?;
        let mut found: Option<(Meta, usize)> = None;
        if data.len() >= PAGE_HEADER + META_BODY
            && let Some(m) = parse_meta(&data[0..PAGE_HEADER + META_BODY])
        {
            let ps = m.page_size as usize;
            if (256..=1 << 20).contains(&ps) && data.len() % ps == 0 {
                found = Some((m, ps));
            }
        }
        if found.is_none() {
            for cand in [4096usize, 65536, 8192, 16384, 32768] {
                if data.len() < cand + PAGE_HEADER + META_BODY {
                    continue;
                }
                if let Some(m) = parse_meta(&data[cand..cand + PAGE_HEADER + META_BODY])
                    && m.page_size as usize == cand
                    && data.len() % cand == 0
                {
                    found = Some((m, cand));
                    break;
                }
            }
        }
        let (meta, page_size) = found.ok_or_else(|| err("no valid meta page"))?;
        if meta.root >= meta.pgid {
            return Err(err("root above high water mark"));
        }
        Ok(Db {
            data,
            page_size,
            meta,
        })
    }

    pub fn meta(&self) -> &Meta {
        &self.meta
    }

    pub fn get(&self, path: &[&str], key: &[u8]) -> io::Result<Option<Vec<u8>>> {
        let mut page = self.load_page(self.meta.root)?;
        for segment in path {
            let entry = self
                .find_bucket_in(&page, segment.as_bytes())?
                .ok_or_else(|| err("bucket not found"))?;
            page = self.bucket_root_bytes(&entry)?;
        }
        match find_in_bytes(&page, key)? {
            Some(e) if e.flags & BUCKET_LEAF_FLAG == 0 => Ok(Some(e.value)),
            _ => Ok(None),
        }
    }

    pub fn has_bucket(&self, path: &[&str]) -> io::Result<bool> {
        let mut page = self.load_page(self.meta.root)?;
        for segment in path {
            match self.find_bucket_in(&page, segment.as_bytes())? {
                Some(entry) => page = self.bucket_root_bytes(&entry)?,
                None => return Ok(false),
            }
        }
        Ok(true)
    }

    fn load_page(&self, pgid: u64) -> io::Result<Vec<u8>> {
        let start = pgid
            .checked_mul(self.page_size as u64)
            .ok_or_else(|| err("pgid overflow"))? as usize;
        let page = self
            .data
            .get(start..start + self.page_size)
            .ok_or_else(|| err("page oob"))?;
        if (Reader { buf: page }).u64(0)? != pgid {
            return Err(err("page id mismatch"));
        }
        page_kind(page)?;
        Ok(page.to_vec())
    }

    fn bucket_root_bytes(&self, entry: &Elem) -> io::Result<Vec<u8>> {
        if entry.value.len() < BUCKET_HEADER {
            return Err(err("short bucket header"));
        }
        let root = Reader { buf: &entry.value }.u64(0)?;
        if root == NO_FREELIST {
            return Err(err("invalid bucket root"));
        }
        if root == 0 {
            let inline = entry
                .value
                .get(BUCKET_HEADER..)
                .ok_or_else(|| err("short inline"))?;
            page_kind(inline)?;
            Ok(inline.to_vec())
        } else {
            self.load_page(root)
        }
    }

    fn find_bucket_in(&self, page: &[u8], name: &[u8]) -> io::Result<Option<Elem>> {
        match page_kind(page)? {
            PageKind::Leaf => {
                for e in leaf_elems(page)? {
                    if e.key == name && e.flags & BUCKET_LEAF_FLAG != 0 {
                        return Ok(Some(e));
                    }
                }
                Ok(None)
            }
            PageKind::Branch => {
                for e in branch_elems(page)? {
                    let child = self.load_page(e.child)?;
                    if let Some(found) = self.find_bucket_in(&child, name)? {
                        return Ok(Some(found));
                    }
                }
                Ok(None)
            }
        }
    }
}

fn find_in_bytes(page: &[u8], key: &[u8]) -> io::Result<Option<Elem>> {
    match page_kind(page)? {
        PageKind::Leaf => {
            for e in leaf_elems(page)? {
                if e.key == key {
                    return Ok(Some(e));
                }
            }
            Ok(None)
        }
        PageKind::Branch => Err(err("unexpected branch at value level")),
    }
}

#[derive(Clone)]
pub enum EntrySpec {
    Kv(String, Vec<u8>),
    Bucket {
        name: String,
        seq: u64,
        node: NodeSpec,
    },
}

#[derive(Clone)]
pub struct NodeSpec {
    pub entries: Vec<EntrySpec>,
}

impl EntrySpec {
    fn key(&self) -> &str {
        match self {
            EntrySpec::Kv(k, _) => k,
            EntrySpec::Bucket { name, .. } => name,
        }
    }
}

fn sorted_tree(node: &NodeSpec) -> NodeSpec {
    let mut entries: Vec<EntrySpec> = node
        .entries
        .iter()
        .map(|e| match e {
            EntrySpec::Kv(k, v) => EntrySpec::Kv(k.clone(), v.clone()),
            EntrySpec::Bucket { name, seq, node } => EntrySpec::Bucket {
                name: name.clone(),
                seq: *seq,
                node: sorted_tree(node),
            },
        })
        .collect();
    entries.sort_by_key(|e| e.key().as_bytes().to_vec());
    NodeSpec { entries }
}

fn node_bytes(node: &NodeSpec) -> usize {
    PAGE_HEADER
        + LEAF_ELEM * node.entries.len()
        + node
            .entries
            .iter()
            .map(|e| match e {
                EntrySpec::Kv(k, v) => k.len() + v.len(),
                EntrySpec::Bucket { name, node, .. } => {
                    name.len() + BUCKET_HEADER + node_bytes(node)
                }
            })
            .sum::<usize>()
}

pub fn write(path: &Path, root: &NodeSpec) -> io::Result<()> {
    let page_size = 4096usize;
    let root = sorted_tree(root);
    let root = &root;
    if node_bytes(root) > page_size {
        return Err(err("spike writer: root node exceeds one page"));
    }
    let mut pages: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut next_pgid = 2u64;
    let root_pgid = assign(root, &mut next_pgid, page_size, &mut pages)?;
    let mut file = vec![0u8; next_pgid as usize * page_size];
    for (pgid, bytes) in &pages {
        let off = *pgid as usize * page_size;
        file[off..off + bytes.len()].copy_from_slice(bytes);
    }
    for (id, txid) in [(0u64, 0u64), (1u64, 1u64)] {
        let mut page = vec![0u8; page_size];
        page[0..8].copy_from_slice(&id.to_le_bytes());
        page[8..10].copy_from_slice(&META_FLAG.to_le_bytes());
        let mut meta = vec![0u8; META_BODY];
        meta[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        meta[4..8].copy_from_slice(&VERSION.to_le_bytes());
        meta[8..12].copy_from_slice(&(page_size as u32).to_le_bytes());
        meta[16..24].copy_from_slice(&root_pgid.to_le_bytes());
        meta[24..32].copy_from_slice(&0u64.to_le_bytes());
        meta[32..40].copy_from_slice(&NO_FREELIST.to_le_bytes());
        meta[40..48].copy_from_slice(&next_pgid.to_le_bytes());
        meta[48..56].copy_from_slice(&txid.to_le_bytes());
        let sum = fnv1a64(&meta[0..56]);
        meta[56..64].copy_from_slice(&sum.to_le_bytes());
        page[PAGE_HEADER..PAGE_HEADER + META_BODY].copy_from_slice(&meta);
        let off = id as usize * page_size;
        file[off..off + page_size].copy_from_slice(&page);
    }
    fs::write(path, file)
}

fn assign(
    node: &NodeSpec,
    next_pgid: &mut u64,
    page_size: usize,
    pages: &mut Vec<(u64, Vec<u8>)>,
) -> io::Result<u64> {
    let mut child_pgids = Vec::new();
    for e in &node.entries {
        if let EntrySpec::Bucket { node, .. } = e {
            if node_bytes(node) > page_size {
                return Err(err("spike writer: nested node exceeds one page"));
            }
            child_pgids.push(assign(node, next_pgid, page_size, pages)?);
        }
    }
    let pgid = *next_pgid;
    *next_pgid += 1;
    let count = node.entries.len() as u16;
    let mut page = vec![0u8; page_size];
    page[0..8].copy_from_slice(&pgid.to_le_bytes());
    page[8..10].copy_from_slice(&LEAF_FLAG.to_le_bytes());
    page[10..12].copy_from_slice(&count.to_le_bytes());

    let mut off = PAGE_HEADER + LEAF_ELEM * node.entries.len();
    let mut child_iter = child_pgids.into_iter();
    for (i, e) in node.entries.iter().enumerate() {
        let elem_off = PAGE_HEADER + i * LEAF_ELEM;
        let (flags, key, value): (u32, &str, Vec<u8>) = match e {
            EntrySpec::Kv(k, v) => (0, k, v.clone()),
            EntrySpec::Bucket { name, seq, .. } => {
                let child = child_iter.next().ok_or_else(|| err("child mismatch"))?;
                let mut v = vec![0u8; BUCKET_HEADER];
                v[0..8].copy_from_slice(&child.to_le_bytes());
                v[8..16].copy_from_slice(&seq.to_le_bytes());
                (BUCKET_LEAF_FLAG, name, v)
            }
        };
        let k = key.as_bytes();
        let sz = k.len() + value.len();
        if off + sz > page_size {
            return Err(err("spike writer: leaf overflow"));
        }
        let pos = (off - elem_off) as u32;
        page[elem_off..elem_off + 4].copy_from_slice(&flags.to_le_bytes());
        page[elem_off + 4..elem_off + 8].copy_from_slice(&pos.to_le_bytes());
        page[elem_off + 8..elem_off + 12].copy_from_slice(&(k.len() as u32).to_le_bytes());
        page[elem_off + 12..elem_off + 16].copy_from_slice(&(value.len() as u32).to_le_bytes());
        page[off..off + k.len()].copy_from_slice(k);
        page[off + k.len()..off + sz].copy_from_slice(&value);
        off += sz;
    }
    pages.push((pgid, page));
    Ok(pgid)
}
