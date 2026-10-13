//! Recycled payload buffers for inbound DATA frames.
//!
//! A decoded DATA payload normally freezes a slice of the codec read buffer,
//! so the buffer allocation stays shared with the payload until the
//! application drops it. The next `reserve` finds the buffer shared, cannot
//! reclaim it, and allocates a new one: with musl that is a fresh mmap of the
//! frame size per frame -- measured 8k mmap + 190k minor faults per GiB,
//! which is most of the h2 cell's kernel time. Copying the payload into a
//! recycled buffer costs one memmove and lets the codec reclaim its own
//! allocation with a memmove and no syscall at all.
//!
//! The pool is per thread, so a `Bytes` dropped on another worker thread just
//! feeds that thread's pool -- it is a cache, not an ownership scheme.

use bytes::{Bytes, BytesMut};
use std::cell::RefCell;

// One spare covers the steady state (frames of one size for the life of a
// transfer); a few extras absorb bursts and mixed frame sizes.
const MAX_POOLED: usize = 8;

thread_local! {
    static POOL: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
}

/// Copy `buf` into a recycled allocation and hand it out as `Bytes`.
pub(super) fn recycle(buf: BytesMut) -> Bytes {
    if buf.is_empty() {
        return Bytes::new();
    }
    let len = buf.len();
    let mut spare = POOL.with(|p| p.borrow_mut().pop());
    if let Some(ref v) = spare {
        if v.capacity() < len {
            spare = None;
        }
    }
    let v = match spare {
        Some(mut v) => {
            v.clear();
            v.extend_from_slice(&buf);
            v
        }
        None => buf.to_vec(),
    };
    // Release the codec buffer before handing out the copy, so the very next
    // reserve finds it uniquely owned and reclaims it in place.
    drop(buf);
    Bytes::from_owner(Owner(v))
}

/// Owns a pooled `Vec` and returns it to the pool when the last `Bytes` copy
/// referencing it dies.
struct Owner(Vec<u8>);

impl AsRef<[u8]> for Owner {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        let mut v = std::mem::take(&mut self.0);
        v.clear();
        // try_with, not with: a pooled buffer may be dropped while the thread
        // local is already tearing down, and a panic in drop is a crash.
        let _ = POOL.try_with(move |p| {
            let mut p = p.borrow_mut();
            if p.len() < MAX_POOLED {
                p.push(v);
            }
        });
    }
}
