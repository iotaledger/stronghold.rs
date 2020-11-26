// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::many_single_char_names)]

use core::{
    alloc::{GlobalAlloc, Layout, LayoutErr},
    ptr,
};

use zeroize::Zeroize;

#[derive(PartialEq, Debug)]
pub enum Error {
    ZeroAllocation,
    Layout(LayoutErr),
}

#[cfg(unix)]
lazy_static! {
    static ref PAGE_SIZE: usize = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
}
#[cfg(unix)]
fn page_size() -> usize {
    *PAGE_SIZE
}

fn pad(x: usize, n: usize) -> usize {
    match x % n {
        0 => 0,
        r => n - r,
    }
}

fn pad_minimizer(a: usize, b: usize, c: usize) -> usize {
    match b % c {
        0 => 0,
        bc => {
            if bc % a == 0 {
                c / a - bc / a
            } else {
                c / a - bc / a - 1
            }
        }
    }
}

fn mmap(n: usize) -> crate::Result<*mut u8> {
    let x = unsafe {
        libc::mmap(
            ptr::null_mut::<u8>() as *mut libc::c_void,
            n,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if x == libc::MAP_FAILED {
        return Err(crate::Error::os("mmap"));
    }
    Ok(x as *mut u8)
}

fn munmap(p: *mut u8, n: usize) -> crate::Result<()> {
    match unsafe { libc::munmap(p as *mut libc::c_void, n) } {
        0 => Ok(()),
        _ => Err(crate::Error::os("munmap")),
    }
}

#[derive(Debug, PartialEq)]
pub struct GuardedAllocation {
    base: *mut u8,
    data_region_start: *mut u8,
    data_region_size: usize,
    data_aligned: *mut u8,
    mmapped_size: usize, // size of the memory mapping (including guard pages)
}

impl GuardedAllocation {
    pub fn unaligned(n: usize) -> crate::Result<Self> {
        Self::aligned(Layout::from_size_align(n, 1).map_err(Error::Layout)?)
    }

    pub fn aligned(l: Layout) -> crate::Result<Self> {
        let n = l.size();
        if n == 0 {
            return Err(Error::ZeroAllocation.into());
        }

        let a = l.align();
        let p = page_size();

        let data_region_size = n + pad(n, p);
        let a = if p % a == 0 {
            let mmapped_size = p + data_region_size + p;
            let base = mmap(mmapped_size)?;
            let i = pad_minimizer(a, n, p);
            Self {
                base,
                data_region_start: unsafe { base.add(p) },
                data_region_size,
                data_aligned: unsafe { base.add(p + i * a) },
                mmapped_size,
            }
        } else if a % p == 0 {
            let x = mmap(a + data_region_size + p)?;
            let i = a / p;
            let j = x as usize / p;
            let o = i - 1 - (j % i);
            let base = unsafe { x.add(o * p) };
            if o > 0 {
                munmap(x, o * p)?;
            }
            let mmapped_size = p + n + pad(n, p) + p;

            if j % i > 0 {
                let end = unsafe { base.add(mmapped_size) };
                munmap(end, (j % i) * p)?;
            }

            Self {
                base,
                data_region_start: unsafe { base.add(p) },
                data_region_size,
                data_aligned: unsafe { base.add(p) },
                mmapped_size,
            }
        } else {
            return Err(crate::Error::unreachable(
                "page size and requested alignment is coprime",
            ));
        };

        a.protect(true, true)?;
        a.lock()?;

        Ok(a)

        // TODO: write canary for the writable page (NB don't write canaries in the guards,
        // then at least they don't reserve physical memory, (assuming COW))
    }

    unsafe fn from_ptr(data: *mut u8, l: Layout) -> Self {
        let p = page_size();
        let n = l.size();
        let data_region_size = n + pad(n, p);
        let mmapped_size = p + data_region_size + p;
        let base = data.offset(-((p + (data as usize) % p) as isize));
        Self {
            base,
            data_region_start: base.add(p),
            data_region_size,
            data_aligned: data,
            mmapped_size,
        }
    }

    pub fn free(&self) -> crate::Result<()> {
        unsafe { core::slice::from_raw_parts_mut(self.data_region_start, self.data_region_size) }.zeroize();
        munmap(self.base, self.mmapped_size)
    }

    pub fn data(&self) -> *mut u8 {
        self.data_aligned
    }

    fn protect(&self, read: bool, write: bool) -> crate::Result<()> {
        let prot = (read as i32 * libc::PROT_READ) | (write as i32 * libc::PROT_WRITE);
        match unsafe { libc::mprotect(self.data_region_start as *mut libc::c_void, self.data_region_size, prot) } {
            0 => Ok(()),
            _ => Err(crate::Error::os("mprotect")),
        }
    }

    fn lock(&self) -> crate::Result<()> {
        match unsafe { libc::mlock(self.data_region_start as *mut libc::c_void, self.data_region_size) } {
            0 => Ok(()),
            _ => Err(crate::Error::os("mlock")),
        }
    }
}

pub struct GuardedAllocator {}

impl GuardedAllocator {
    pub const fn new() -> Self {
        Self {}
    }
}

unsafe impl GlobalAlloc for GuardedAllocator {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        GuardedAllocation::aligned(l).map(|a| a.data()).unwrap()
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        GuardedAllocation::from_ptr(p, l).free().unwrap()
    }
}

#[cfg(target_os = "linux")]
pub fn seccomp_spec() -> crate::seccomp::Spec {
    crate::seccomp::Spec {
        anonymous_mmap: true,
        munmap: true,
        mprotect: true,
        mlock: true,
        ..crate::seccomp::Spec::default()
    }
}

#[cfg(test)]
mod tests {
    #[global_allocator]
    static ALLOC: GuardedAllocator = GuardedAllocator::new();

    use super::*;
    use rand::{rngs::OsRng, Rng};

    fn page_size_exponent() -> u32 {
        let mut p = 1;
        let mut k = 0;
        while p != page_size() {
            p *= 2;
            k += 1;
        }
        k as u32
    }

    fn fresh_layout() -> Layout {
        let mut n = 0;
        while n == 0 {
            n = OsRng.gen::<usize>() % 3 * page_size();
        }

        let a = 2usize.pow(OsRng.gen::<u32>() % page_size_exponent() + 3);

        Layout::from_size_align(n, a).unwrap()
    }

    fn do_test_write(p: *mut u8, n: usize) {
        let bs = unsafe { core::slice::from_raw_parts_mut(p, n) };
        for b in bs.iter() {
            assert_eq!(*b, 0u8);
        }

        OsRng.fill(bs);
    }

    fn do_sized_alloc_test(n: usize) -> crate::Result<()> {
        let a = GuardedAllocation::unaligned(n)?;

        do_test_write(a.data(), n);

        a.free()?;

        Ok(())
    }

    #[test]
    fn allocate_whole_page() -> crate::Result<()> {
        do_sized_alloc_test(page_size())
    }

    #[test]
    fn allocate_less_than_a_whole_page() -> crate::Result<()> {
        do_sized_alloc_test(1)
    }

    #[test]
    fn allocate_little_more_than_a_whole_page() -> crate::Result<()> {
        do_sized_alloc_test(page_size() + 1)
    }

    #[test]
    fn allocate_random_sizes() -> crate::Result<()> {
        for _ in 1..10 {
            do_sized_alloc_test(OsRng.gen::<usize>() % 1024 * 1024)?
        }
        Ok(())
    }

    #[test]
    fn alignment() -> crate::Result<()> {
        for _ in 1..100 {
            let l = fresh_layout();
            let a = GuardedAllocation::aligned(l)?;
            assert_eq!((a.data() as usize) % l.align(), 0);
            do_test_write(a.data(), l.size());
            a.free()?;
        }

        Ok(())
    }

    #[test]
    fn zero_allocation() -> crate::Result<()> {
        assert_eq!(GuardedAllocation::unaligned(0), Err(Error::ZeroAllocation.into()),);
        Ok(())
    }

    #[test]
    fn guard_pages_pre_read() -> crate::Result<()> {
        let l = fresh_layout();
        let a = GuardedAllocation::aligned(l)?;

        assert_eq!(
            crate::zone::soft(|| {
                for i in 0..page_size() {
                    let _ = unsafe {
                        core::ptr::read_unaligned(a.data().offset(-(i as isize)));
                    };
                }
            }),
            Err(crate::Error::ZoneError(crate::zone::Error::Signal {
                signo: libc::SIGSEGV
            }))
        );

        Ok(())
    }

    #[test]
    fn guard_pages_pre_write() -> crate::Result<()> {
        let l = fresh_layout();
        let a = GuardedAllocation::aligned(l)?;

        assert_eq!(
            crate::zone::soft(|| {
                for i in 0..page_size() {
                    unsafe {
                        core::ptr::write_unaligned(a.data().offset(-(i as isize)), OsRng.gen());
                    }
                }
            }),
            Err(crate::Error::ZoneError(crate::zone::Error::Signal {
                signo: libc::SIGSEGV
            }))
        );

        Ok(())
    }

    #[test]
    fn guard_pages_post_read() -> crate::Result<()> {
        let l = fresh_layout();
        let a = GuardedAllocation::aligned(l)?;

        assert_eq!(
            crate::zone::soft(|| {
                for i in 0..page_size() {
                    let _ = unsafe {
                        core::ptr::read_unaligned(a.data().add(l.size() + i));
                    };
                }
            }),
            Err(crate::Error::ZoneError(crate::zone::Error::Signal {
                signo: libc::SIGSEGV
            }))
        );

        Ok(())
    }

    #[test]
    fn guard_pages_post_write() -> crate::Result<()> {
        let l = fresh_layout();
        let a = GuardedAllocation::aligned(l)?;

        assert_eq!(
            crate::zone::soft(|| {
                for i in 0..page_size() {
                    unsafe {
                        core::ptr::write_unaligned(a.data().add(l.size() + i), OsRng.gen());
                    }
                }
            }),
            Err(crate::Error::ZoneError(crate::zone::Error::Signal {
                signo: libc::SIGSEGV
            }))
        );

        Ok(())
    }

    #[test]
    fn vectors() -> crate::Result<()> {
        extern crate alloc;
        use alloc::vec::Vec;

        let mut bs: Vec<u8> = Vec::with_capacity(10);
        for _ in 1..100 {
            bs.push(OsRng.gen());
        }

        Ok(())
    }

    #[test]
    fn inside_zone() -> crate::Result<()> {
        let l = fresh_layout();
        crate::zone::soft(|| {
            if cfg!(target_os = "linux") {
                seccomp_spec().with_getrandom().apply().unwrap();
            }

            let a = GuardedAllocation::aligned(l).unwrap();
            do_test_write(a.data(), l.size());
            a.free().unwrap();
        })
    }
}
