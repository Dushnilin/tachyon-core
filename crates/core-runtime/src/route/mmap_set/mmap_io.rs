//! Safe cross-platform Memory-Mapped file wrapper.
//!
//! On Linux/Unix platforms (OpenWrt routers), maps files directly via `mmap(2)`
//! into virtual address space with zero heap allocation and on-demand page faulting.
//! On non-Unix platforms (Windows host during dev/testing), provides a seamless
//! buffer fallback implementing the same `Deref<Target = [u8]>` contract.

use std::fs::File;
use std::io;
use std::ops::Deref;
use std::path::Path;

pub struct MmapBuffer {
    #[cfg(unix)]
    ptr: *mut std::ffi::c_void,
    #[cfg(unix)]
    len: usize,
    #[cfg(not(unix))]
    data: Box<[u8]>,
}

unsafe impl Send for MmapBuffer {}
unsafe impl Sync for MmapBuffer {}

impl MmapBuffer {
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        let len = metadata.len() as usize;
        if len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "empty rule-set file",
            ));
        }

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = file.as_raw_fd();
            let ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    libc::PROT_READ,
                    libc::MAP_SHARED,
                    fd,
                    0,
                )
            };
            if ptr == libc::MAP_FAILED {
                return Err(io::Error::last_os_error());
            }

            // Advisory hint: we will access randomly during packet routing
            unsafe {
                libc::madvise(ptr, len, libc::MADV_RANDOM);
            }

            Ok(Self { ptr, len })
        }

        #[cfg(not(unix))]
        {
            use std::io::Read;
            let mut file = file;
            let mut buf = vec![0u8; len];
            file.read_exact(&mut buf)?;
            Ok(Self {
                data: buf.into_boxed_slice(),
            })
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        #[cfg(unix)]
        {
            // Anonymous memory mapping for tests/in-memory compilation
            let len = bytes.len();
            if len == 0 {
                return Self {
                    ptr: std::ptr::null_mut(),
                    len: 0,
                };
            }
            let ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if ptr == libc::MAP_FAILED {
                // fallback to copying
                return Self {
                    ptr: std::ptr::null_mut(),
                    len: 0,
                };
            }
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr as *mut u8, len);
                libc::mprotect(ptr, len, libc::PROT_READ);
            }
            Self { ptr, len }
        }

        #[cfg(not(unix))]
        {
            Self {
                data: bytes.to_vec().into_boxed_slice(),
            }
        }
    }
}

impl Deref for MmapBuffer {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        #[cfg(unix)]
        {
            if self.ptr.is_null() || self.len == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(self.ptr as *const u8, self.len) }
            }
        }

        #[cfg(not(unix))]
        {
            &self.data
        }
    }
}

#[cfg(unix)]
impl Drop for MmapBuffer {
    fn drop(&mut self) {
        if !self.ptr.is_null() && self.len > 0 {
            unsafe {
                libc::munmap(self.ptr, self.len);
            }
        }
    }
}
