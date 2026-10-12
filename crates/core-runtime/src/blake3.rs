//! BLAKE3 in portable pure Rust: no dependencies, no SIMD, no C.
//!
//! Four call sites, all connection setup (vless-enc derive and tickets,
//! shadowsocks-2022 subkey), so the scalar path is the right trade — it is
//! bit-identical to what the `blake3` crate emits and builds anywhere,
//! including the mipsel tier-3 target that has no prebuilt std at all.
//!
//! Spec: <https://github.com/BLAKE3-team/BLAKE3>. The goldens in `tests`
//! were captured from blake3 1.8.7 before the crate was dropped from the
//! tree; the wire must not drift from them.

const OUT_LEN: usize = 32;
const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;
const DERIVE_KEY_CONTEXT: u32 = 1 << 5;
const DERIVE_KEY_MATERIAL: u32 = 1 << 6;

const IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

/// The 32-byte hash output — `blake3::Hash` at the call sites that kept it.
#[derive(Clone, Copy)]
pub struct Hash([u8; OUT_LEN]);

impl Hash {
    pub fn as_bytes(&self) -> &[u8; OUT_LEN] {
        &self.0
    }
}

impl From<Hash> for [u8; OUT_LEN] {
    fn from(hash: Hash) -> Self {
        hash.0
    }
}

fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(mx);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(my);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

fn round(v: &mut [u32; 16], m: &[u32; 16]) {
    // columns
    g(v, 0, 4, 8, 12, m[0], m[1]);
    g(v, 1, 5, 9, 13, m[2], m[3]);
    g(v, 2, 6, 10, 14, m[4], m[5]);
    g(v, 3, 7, 11, 15, m[6], m[7]);
    // diagonals
    g(v, 0, 5, 10, 15, m[8], m[9]);
    g(v, 1, 6, 11, 12, m[10], m[11]);
    g(v, 2, 7, 8, 13, m[12], m[13]);
    g(v, 3, 4, 9, 14, m[14], m[15]);
}

/// The BLAKE3 compression: 7 rounds, output feed-forward against `cv`.
fn compress(
    cv: &[u32; 8],
    block: &[u8; BLOCK_LEN],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let mut m = [0u32; 16];
    for (word, bytes) in m.iter_mut().zip(block.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*bytes);
    }
    let mut v = [
        cv[0],
        cv[1],
        cv[2],
        cv[3],
        cv[4],
        cv[5],
        cv[6],
        cv[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter as u32,
        (counter >> 32) as u32,
        block_len,
        flags,
    ];
    for round_no in 0..7 {
        round(&mut v, &m);
        if round_no < 6 {
            let old = m;
            for (i, word) in m.iter_mut().enumerate() {
                *word = old[MSG_PERMUTATION[i]];
            }
        }
    }
    let mut out = [0u32; 16];
    for i in 0..8 {
        out[i] = v[i] ^ v[i + 8];
        out[i + 8] = v[i + 8] ^ cv[i];
    }
    out
}

fn words_from_bytes(bytes: &[u8; OUT_LEN]) -> [u32; 8] {
    let mut words = [0u32; 8];
    for (word, chunk) in words.iter_mut().zip(bytes.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*chunk);
    }
    words
}

/// One compression, remembered so a later choice (interior CV, or the ROOT
/// flag at finalize time) can re-run it on the same inputs.
struct Output {
    input_cv: [u32; 8],
    block: [u8; BLOCK_LEN],
    counter: u64,
    block_len: u32,
    flags: u32,
}

impl Output {
    fn chaining_value(&self) -> [u32; 8] {
        compress(
            &self.input_cv,
            &self.block,
            self.counter,
            self.block_len,
            self.flags,
        )[..8]
            .try_into()
            .unwrap()
    }

    fn root_output_key_bytes(&self) -> [u8; OUT_LEN] {
        let out = compress(
            &self.input_cv,
            &self.block,
            self.counter,
            self.block_len,
            self.flags | ROOT,
        );
        let mut bytes = [0u8; OUT_LEN];
        for (chunk, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(&out[..8]) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }
}

fn parent_output(key: [u32; 8], left: [u32; 8], right: [u32; 8], flags: u32) -> Output {
    let mut block = [0u8; BLOCK_LEN];
    for (chunk, word) in block
        .as_chunks_mut::<4>()
        .0
        .iter_mut()
        .zip(left.iter().chain(&right))
    {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    Output {
        input_cv: key,
        block,
        counter: 0,
        block_len: BLOCK_LEN as u32,
        flags: flags | PARENT,
    }
}

fn parent_cv(key: [u32; 8], left: [u32; 8], right: [u32; 8], flags: u32) -> [u32; 8] {
    parent_output(key, left, right, flags).chaining_value()
}

/// At most 1024 bytes, at most 16 blocks, one chunk counter.
struct ChunkState {
    chaining_value: [u32; 8],
    chunk_counter: u64,
    block: [u8; BLOCK_LEN],
    block_len: usize,
    blocks_compressed: usize,
    flags: u32,
}

impl ChunkState {
    fn new(chaining_value: [u32; 8], chunk_counter: u64, flags: u32) -> Self {
        Self {
            chaining_value,
            chunk_counter,
            block: [0; BLOCK_LEN],
            block_len: 0,
            blocks_compressed: 0,
            flags,
        }
    }

    fn len(&self) -> usize {
        self.blocks_compressed * BLOCK_LEN + self.block_len
    }

    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.block_len == BLOCK_LEN {
                // Input still follows a full block, so this one is interior:
                // never CHUNK_END — only output() may know the chunk's end.
                let mut flags = self.flags;
                if self.blocks_compressed == 0 {
                    flags |= CHUNK_START;
                }
                let out = compress(
                    &self.chaining_value,
                    &self.block,
                    self.chunk_counter,
                    BLOCK_LEN as u32,
                    flags,
                );
                self.chaining_value = out[..8].try_into().unwrap();
                self.blocks_compressed += 1;
                self.block_len = 0;
            }
            let take = (BLOCK_LEN - self.block_len).min(input.len());
            let end = self.block_len + take;
            self.block[self.block_len..end].copy_from_slice(&input[..take]);
            self.block_len = end;
            input = &input[take..];
        }
    }

    fn output(&self) -> Output {
        let mut flags = self.flags;
        if self.blocks_compressed == 0 {
            flags |= CHUNK_START;
        }
        flags |= CHUNK_END;
        // The final block is the valid bytes zero-padded (spec).
        let mut block = [0u8; BLOCK_LEN];
        block[..self.block_len].copy_from_slice(&self.block[..self.block_len]);
        Output {
            input_cv: self.chaining_value,
            block,
            counter: self.chunk_counter,
            block_len: self.block_len as u32,
            flags,
        }
    }
}

pub struct Hasher {
    key: [u32; 8],
    chunk: ChunkState,
    /// Completed subtrees, strictly decreasing sizes bottom to top: the
    /// tree shape lives in this stack, no counters needed at finalize.
    cv_stack: Vec<([u32; 8], u64)>,
    flags: u32,
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher {
    pub fn new() -> Self {
        Self::with_key(IV, 0)
    }

    /// Derive-key construction: hash the context (stage 1), then stream the
    /// key material under the result (stage 2).
    pub fn new_derive_key(context: &str) -> Self {
        let context_key = derive_key_context(context.as_bytes());
        Self::with_key(words_from_bytes(&context_key), DERIVE_KEY_MATERIAL)
    }

    fn with_key(key: [u32; 8], flags: u32) -> Self {
        Self {
            key,
            chunk: ChunkState::new(key, 0, flags),
            cv_stack: Vec::new(),
            flags,
        }
    }

    pub fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.chunk.len() == CHUNK_LEN {
                let cv = self.chunk.output().chaining_value();
                self.push(cv, 1);
                let counter = self.chunk.chunk_counter + 1;
                self.chunk = ChunkState::new(self.key, counter, self.flags);
            }
            let take = (CHUNK_LEN - self.chunk.len()).min(input.len());
            self.chunk.update(&input[..take]);
            input = &input[take..];
        }
    }

    pub fn finalize(&self) -> Hash {
        Hash(self.finalize_output().root_output_key_bytes())
    }

    fn finalize_output(&self) -> Output {
        let mut output = self.chunk.output();
        // Newest subtree first: it is the right child of everything older.
        for &(cv, _) in self.cv_stack.iter().rev() {
            let right = output.chaining_value();
            output = parent_output(self.key, cv, right, self.flags);
        }
        output
    }

    /// Append a completed subtree CV, merging equal sizes into their parent.
    fn push(&mut self, mut cv: [u32; 8], mut size: u64) {
        while let Some((_, top_size)) = self.cv_stack.last().copied() {
            if top_size != size {
                break;
            }
            let (left, _) = self.cv_stack.pop().expect("stack was just non-empty");
            cv = parent_cv(self.key, left, cv, self.flags);
            size *= 2;
        }
        self.cv_stack.push((cv, size));
    }
}

fn derive_key_context(context: &[u8]) -> [u8; OUT_LEN] {
    let mut hasher = Hasher::with_key(IV, DERIVE_KEY_CONTEXT);
    hasher.update(context);
    hasher.finalize().0
}

/// The derive-key construction over raw context bytes. The reference side
/// hashes Go strings, which carry arbitrary bytes (pfs pubkey, server
/// random), so byte contexts must feed the hash unmodified — this is what
/// upstream's `derive_key(&str, ..)` does once the bytes are valid UTF-8.
pub fn derive_key_bytes(context: &[u8], key_material: &[u8]) -> [u8; OUT_LEN] {
    let context_key = derive_key_context(context);
    let mut hasher = Hasher::with_key(words_from_bytes(&context_key), DERIVE_KEY_MATERIAL);
    hasher.update(key_material);
    hasher.finalize().0
}

pub fn derive_key(context: &str, key_material: &[u8]) -> [u8; OUT_LEN] {
    derive_key_bytes(context.as_bytes(), key_material)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i & 0xFF) as u8).collect()
    }

    fn hash_of(data: &[u8]) -> [u8; OUT_LEN] {
        let mut hasher = Hasher::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Pinned against blake3 1.8.7 outputs, captured while the crate was
    /// still in the tree: empty and single-chunk input, a multi-chunk tree,
    /// both derive stages, and the binary context the vless handshake uses.
    #[test]
    fn golden_vectors() {
        let key = [0x42u8; 32];
        let binary = [0xFF, 0x00, 0xC3, 0x28, 0x80, 0xF0, 0x9F, 0x92];
        let (master, salt) = ([7u8; 16], [9u8; 32]);
        let mut ss = Hasher::new_derive_key("shadowsocks 2022 session subkey");
        ss.update(&master);
        ss.update(&salt);

        for (name, got, want) in [
            (
                "empty",
                hash_of(&[]),
                "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
            ),
            (
                "1024",
                hash_of(&pattern(1024)),
                "882179b8dbccd285cda241d968cfcccb3156c5edac2fa3761bb6eda7ff8cb172",
            ),
            (
                "100000",
                hash_of(&pattern(100_000)),
                "b720e83f6661ceace1865722b4f0d1668a2d0815c79effa75bb80569d3e50ca3",
            ),
            (
                "vless",
                derive_key("VLESS", &key),
                "cde773295b49d4fd1acbb35e939192d44f89bb1159d1addc52cb1b5ab39b5946",
            ),
            (
                "empty_ctx",
                derive_key("", &[1, 2, 3]),
                "01fb071d2e23f11eed33582ae8238ff089825011cd451e6954b173239b0f36c7",
            ),
            (
                "binary",
                derive_key_bytes(&binary, &key),
                "4451382280b53cfedf471e21ab6d875d19d59c0af168c12930b2929a6258a917",
            ),
            (
                "ss",
                ss.finalize().into(),
                "98ec231e82aa84b15b39f3bbc2e424312bea24c39ffa03f8c2c4d587330f3458",
            ),
        ] {
            assert_eq!(hex(&got), want, "{name}");
        }
    }

    /// The str variant is a thin wrapper over the byte variant: contexts
    /// that happen to be UTF-8 must derive identically either way.
    #[test]
    fn str_and_bytes_agree() {
        let key = [0x42u8; 32];
        for ctx in [
            "",
            "VLESS",
            "shadowsocks 2022 session subkey",
            "unicode контекст",
        ] {
            assert_eq!(
                derive_key(ctx, &key),
                derive_key_bytes(ctx.as_bytes(), &key),
                "ctx {ctx:?}"
            );
        }
    }
}
