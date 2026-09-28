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

/// A bucket's key/value pairs, in key order.
pub type BucketEntries = Vec<(String, Vec<u8>)>;

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
        // the bucket root may be a branch page when the bucket is wide
        match self.find_in_page(&page, key)? {
            Some(e) if e.flags & BUCKET_LEAF_FLAG == 0 => Ok(Some(e.value)),
            _ => Ok(None),
        }
    }

    /// Depth-first lookup of a key in a node, descending branch pages.
    fn find_in_page(&self, page: &[u8], key: &[u8]) -> io::Result<Option<Elem>> {
        match page_kind(page)? {
            PageKind::Leaf => find_in_bytes(page, key),
            PageKind::Branch => {
                for e in branch_elems(page)? {
                    let child = self.load_page(e.child)?;
                    if let Some(found) = self.find_in_page(&child, key)? {
                        return Ok(Some(found));
                    }
                }
                Ok(None)
            }
        }
    }

    /// Every top-level bucket name, in key order.
    pub fn bucket_names(&self) -> io::Result<Vec<String>> {
        let mut out = Vec::new();
        self.collect_buckets(self.meta.root, &mut out)?;
        Ok(out)
    }

    /// Every key/value of a bucket (depth first, in key order).
    pub fn bucket_page(&self, path: &[&str]) -> io::Result<Option<BucketEntries>> {
        let mut page = self.load_page(self.meta.root)?;
        for segment in path {
            let entry = self
                .find_bucket_in(&page, segment.as_bytes())?
                .ok_or_else(|| err("bucket not found"))?;
            page = self.bucket_root_bytes(&entry)?;
        }
        let mut out = Vec::new();
        self.collect_pairs(&page, &mut out)?;
        Ok(Some(out))
    }

    fn collect_buckets(&self, pgid: u64, out: &mut Vec<String>) -> io::Result<()> {
        let page = self.load_page(pgid)?;
        for elem in self.all_elems(&page)? {
            if elem.flags & BUCKET_LEAF_FLAG != 0 {
                out.push(String::from_utf8_lossy(&elem.key).to_string());
            }
        }
        Ok(())
    }

    fn collect_pairs(&self, page: &[u8], out: &mut Vec<(String, Vec<u8>)>) -> io::Result<()> {
        for elem in self.all_elems(page)? {
            if elem.flags & BUCKET_LEAF_FLAG != 0 {
                continue;
            }
            out.push((String::from_utf8_lossy(&elem.key).to_string(), elem.value));
        }
        Ok(())
    }

    /// All elements of a node, descending branch pages (keys stay sorted).
    fn all_elems(&self, page: &[u8]) -> io::Result<Vec<Elem>> {
        match page_kind(page)? {
            PageKind::Leaf => leaf_elems(page),
            PageKind::Branch => {
                let mut out = Vec::new();
                for elem in branch_elems(page)? {
                    let child = self.load_page(elem.child)?;
                    out.extend(self.all_elems(&child)?);
                }
                Ok(out)
            }
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

    /// A page plus its overflow continuation pages, so a leaf whose value
    /// spans several physical pages parses in one buffer.
    fn load_page(&self, pgid: u64) -> io::Result<Vec<u8>> {
        let start = pgid
            .checked_mul(self.page_size as u64)
            .ok_or_else(|| err("pgid overflow"))? as usize;
        let first = self
            .data
            .get(start..start + self.page_size)
            .ok_or_else(|| err("page oob"))?;
        if (Reader { buf: first }).u64(0)? != pgid {
            return Err(err("page id mismatch"));
        }
        let overflow = (Reader { buf: first }).u32(12)? as usize;
        let total = (overflow + 1) * self.page_size;
        let full = self
            .data
            .get(start..start + total)
            .ok_or_else(|| err("overflow page oob"))?;
        page_kind(full)?;
        Ok(full.to_vec())
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

/// One leaf element of a B+tree node.
#[derive(Clone)]
struct Inode {
    key: Vec<u8>,
    flags: u32,
    value: Vec<u8>,
}

/// A bbolt writer: builds the tree bottom-up, spilling large nodes across
/// overflow pages and splitting wide nodes behind branch pages, so the file is
/// byte-compatible with go.etcd.io/bbolt readers.
struct Writer {
    page_size: usize,
    next_pgid: u64,
    file: Vec<u8>,
}

impl Writer {
    fn new(page_size: usize) -> Self {
        Self {
            page_size,
            next_pgid: 2,
            file: vec![0u8; 2 * page_size],
        }
    }

    fn alloc(&mut self, npages: usize) -> u64 {
        let pgid = self.next_pgid;
        self.next_pgid += npages as u64;
        let end = (pgid as usize + npages) * self.page_size;
        if self.file.len() < end {
            self.file.resize(end, 0);
        }
        pgid
    }

    /// Materialize a node and everything under it; returns (root pgid, first
    /// key) so a parent branch can reference it.
    fn materialize(&mut self, node: &NodeSpec) -> io::Result<(u64, Vec<u8>)> {
        let mut inodes = Vec::with_capacity(node.entries.len());
        for entry in &node.entries {
            match entry {
                EntrySpec::Kv(key, value) => inodes.push(Inode {
                    key: key.as_bytes().to_vec(),
                    flags: 0,
                    value: value.clone(),
                }),
                EntrySpec::Bucket { name, seq, node } => {
                    let (child_pgid, _) = self.materialize(node)?;
                    let mut value = vec![0u8; BUCKET_HEADER];
                    value[0..8].copy_from_slice(&child_pgid.to_le_bytes());
                    value[8..16].copy_from_slice(&seq.to_le_bytes());
                    inodes.push(Inode {
                        key: name.as_bytes().to_vec(),
                        flags: BUCKET_LEAF_FLAG,
                        value,
                    });
                }
            }
        }
        self.spill(inodes)
    }

    fn spill(&mut self, inodes: Vec<Inode>) -> io::Result<(u64, Vec<u8>)> {
        if inodes.is_empty() {
            let pgid = self.write_leaf(&[]);
            return Ok((pgid, Vec::new()));
        }
        let first_key = inodes[0].key.clone();
        let leaves = self.partition(&inodes);
        if leaves.len() == 1 {
            // one logical node: overflow pages if a value is large
            let pgid = self.write_leaf(&leaves[0]);
            return Ok((pgid, first_key));
        }
        let mut refs = Vec::with_capacity(leaves.len());
        for leaf in &leaves {
            let pgid = self.write_leaf(leaf);
            refs.push((leaf[0].key.clone(), pgid));
        }
        let branch_pgid = self.build_branch(refs);
        Ok((branch_pgid, first_key))
    }

    /// Greedy split into leaves that fit a page; a single oversized inode gets
    /// its own leaf and spills over.
    fn partition(&self, inodes: &[Inode]) -> Vec<Vec<Inode>> {
        let mut leaves: Vec<Vec<Inode>> = Vec::new();
        let mut current: Vec<Inode> = Vec::new();
        let mut size = PAGE_HEADER;
        for inode in inodes {
            let elem = LEAF_ELEM + inode.key.len() + inode.value.len();
            if !current.is_empty() && size + elem > self.page_size {
                leaves.push(std::mem::take(&mut current));
                size = PAGE_HEADER;
            }
            current.push(inode.clone());
            size += elem;
        }
        if !current.is_empty() {
            leaves.push(current);
        }
        leaves
    }

    fn write_leaf(&mut self, inodes: &[Inode]) -> u64 {
        let total = PAGE_HEADER
            + LEAF_ELEM * inodes.len()
            + inodes
                .iter()
                .map(|inode| inode.key.len() + inode.value.len())
                .sum::<usize>();
        let npages = total.div_ceil(self.page_size).max(1);
        let pgid = self.alloc(npages);
        let base = pgid as usize * self.page_size;
        self.file[base..base + 8].copy_from_slice(&pgid.to_le_bytes());
        self.file[base + 8..base + 10].copy_from_slice(&LEAF_FLAG.to_le_bytes());
        self.file[base + 10..base + 12].copy_from_slice(&(inodes.len() as u16).to_le_bytes());
        self.file[base + 12..base + 16].copy_from_slice(&((npages - 1) as u32).to_le_bytes());
        let mut data_off = base + PAGE_HEADER + LEAF_ELEM * inodes.len();
        for (i, inode) in inodes.iter().enumerate() {
            let elem = base + PAGE_HEADER + i * LEAF_ELEM;
            let pos = (data_off - elem) as u32;
            self.file[elem..elem + 4].copy_from_slice(&inode.flags.to_le_bytes());
            self.file[elem + 4..elem + 8].copy_from_slice(&pos.to_le_bytes());
            self.file[elem + 8..elem + 12].copy_from_slice(&(inode.key.len() as u32).to_le_bytes());
            self.file[elem + 12..elem + 16]
                .copy_from_slice(&(inode.value.len() as u32).to_le_bytes());
            self.file[data_off..data_off + inode.key.len()].copy_from_slice(&inode.key);
            data_off += inode.key.len();
            self.file[data_off..data_off + inode.value.len()].copy_from_slice(&inode.value);
            data_off += inode.value.len();
        }
        pgid
    }

    /// Branch pages, recursing into branch-of-branches when the index is wide.
    fn build_branch(&mut self, refs: Vec<(Vec<u8>, u64)>) -> u64 {
        if branch_size(&refs) <= self.page_size {
            return self.write_branch_page(&refs);
        }
        let mut groups: Vec<Vec<(Vec<u8>, u64)>> = Vec::new();
        let mut current: Vec<(Vec<u8>, u64)> = Vec::new();
        let mut size = PAGE_HEADER;
        for item in refs {
            let elem = BRANCH_ELEM + item.0.len();
            if !current.is_empty() && size + elem > self.page_size {
                groups.push(std::mem::take(&mut current));
                size = PAGE_HEADER;
            }
            current.push(item);
            size += elem;
        }
        if !current.is_empty() {
            groups.push(current);
        }
        let mut child_refs = Vec::with_capacity(groups.len());
        for group in groups {
            let first = group[0].0.clone();
            let pgid = self.write_branch_page(&group);
            child_refs.push((first, pgid));
        }
        self.build_branch(child_refs)
    }

    fn write_branch_page(&mut self, refs: &[(Vec<u8>, u64)]) -> u64 {
        let pgid = self.alloc(1);
        let base = pgid as usize * self.page_size;
        self.file[base..base + 8].copy_from_slice(&pgid.to_le_bytes());
        self.file[base + 8..base + 10].copy_from_slice(&BRANCH_FLAG.to_le_bytes());
        self.file[base + 10..base + 12].copy_from_slice(&(refs.len() as u16).to_le_bytes());
        let mut data_off = base + PAGE_HEADER + BRANCH_ELEM * refs.len();
        for (i, (key, child)) in refs.iter().enumerate() {
            let elem = base + PAGE_HEADER + i * BRANCH_ELEM;
            let pos = (data_off - elem) as u32;
            self.file[elem..elem + 4].copy_from_slice(&pos.to_le_bytes());
            self.file[elem + 4..elem + 8].copy_from_slice(&(key.len() as u32).to_le_bytes());
            self.file[elem + 8..elem + 16].copy_from_slice(&child.to_le_bytes());
            self.file[data_off..data_off + key.len()].copy_from_slice(key);
            data_off += key.len();
        }
        pgid
    }

    fn write_meta(&mut self, root_pgid: u64) {
        let high_water = self.next_pgid;
        for (id, txid) in [(0u64, 0u64), (1u64, 1u64)] {
            let mut page = vec![0u8; self.page_size];
            page[0..8].copy_from_slice(&id.to_le_bytes());
            page[8..10].copy_from_slice(&META_FLAG.to_le_bytes());
            let mut meta = vec![0u8; META_BODY];
            meta[0..4].copy_from_slice(&MAGIC.to_le_bytes());
            meta[4..8].copy_from_slice(&VERSION.to_le_bytes());
            meta[8..12].copy_from_slice(&(self.page_size as u32).to_le_bytes());
            meta[16..24].copy_from_slice(&root_pgid.to_le_bytes());
            meta[24..32].copy_from_slice(&0u64.to_le_bytes());
            meta[32..40].copy_from_slice(&NO_FREELIST.to_le_bytes());
            meta[40..48].copy_from_slice(&high_water.to_le_bytes());
            meta[48..56].copy_from_slice(&txid.to_le_bytes());
            let sum = fnv1a64(&meta[0..56]);
            meta[56..64].copy_from_slice(&sum.to_le_bytes());
            page[PAGE_HEADER..PAGE_HEADER + META_BODY].copy_from_slice(&meta);
            let off = id as usize * self.page_size;
            self.file[off..off + self.page_size].copy_from_slice(&page);
        }
    }
}

fn branch_size(refs: &[(Vec<u8>, u64)]) -> usize {
    PAGE_HEADER + BRANCH_ELEM * refs.len() + refs.iter().map(|r| r.0.len()).sum::<usize>()
}

pub fn write(path: &Path, root: &NodeSpec) -> io::Result<()> {
    let root = sorted_tree(root);
    let mut writer = Writer::new(4096);
    let (root_pgid, _) = writer.materialize(&root)?;
    writer.write_meta(root_pgid);
    fs::write(path, &writer.file)
}
