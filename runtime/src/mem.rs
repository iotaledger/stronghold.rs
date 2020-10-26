// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::{
    alloc::{GlobalAlloc, Layout, LayoutErr},
    ptr,
};

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
fn page_size() -> usize { *PAGE_SIZE }

pub struct GuardedAllocator { }

impl GuardedAllocator {
    pub const fn new() -> Self { Self { } }

    pub fn alloc(&self, l: Layout) -> crate::Result<*mut u8> {
        Allocation::new(l).map(|a| a.data)
    }

    pub fn dealloc(&self, p: *mut u8, l: Layout) -> crate::Result<()> {
        Allocation::from_ptr(p, l).free()
    }

    pub fn alloc_unaligned(&self, n: usize) -> crate::Result<*mut u8> {
        self.alloc(Layout::from_size_align(n, 1).map_err(|e| Error::Layout(e))?)
    }

    pub fn dealloc_unaligned(&self, p: *mut u8, n: usize) -> crate::Result<()> {
        self.dealloc(p, Layout::from_size_align(n, 1).map_err(|e| Error::Layout(e))?)
    }
}

unsafe impl GlobalAlloc for GuardedAllocator {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        Allocation::new(l).map(|a| a.data).unwrap()
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        Allocation::from_ptr(p, l).free().unwrap()
    }
}

pub struct Allocation {
    base: *mut u8,
    data: *mut u8,
    total_size: usize, // NB size of the memory mapping (including guard pages)
}

impl Allocation {
    pub fn new(l: Layout) -> crate::Result<Self> {
        if l.size() == 0 {
            return Err(Error::ZeroAllocation.into());
        }

        let p = page_size();
        let (total_size, offset) = if p % l.align() == 0 {
            let n = l.pad_to_align().size();
            let (q, r) = num::integer::div_rem(n, p);
            if r == 0 {
                ((2 + q)*p, Some(p))
            } else {
                ((2 + 1 + q)*p, Some(p + (p - r)))
            }
        } else {
            let i = Layout::from_size_align(l.align(), p).map_err(|e| Error::Layout(e))?
                .pad_to_align().size();
            let k = l.align_to(p).map_err(|e| Error::Layout(e))?.pad_to_align().size();
            (2*p + i + k, None)
        };

        let base = unsafe {
            libc::mmap(
                ptr::null_mut::<u8>() as *mut libc::c_void,
                total_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1, 0)
        };
        if base == libc::MAP_FAILED {
            return Err(crate::Error::os("mmap"));
        }
        let base = base as *mut u8;

        // TODO: write canary for the writable page (NB don't write canaries in the guards,
        // then at least they don't reserve physical memory, (assuming COW))
        // TODO: lock the guard pages
        // TODO: mlock the data pages
        // TODO: zero the data pages

        let data = match offset {
            Some(o) => unsafe { base.offset(o as isize) },
            None => unsafe {
                let q = base.offset(p as isize);
                q.offset(q.align_offset(l.align()) as isize)
            }
        };

        Ok(Self { base, data, total_size })
    }

    pub fn from_ptr(data: *mut u8, l: Layout) -> Self {
        let p = page_size();
        let (total_size, offset) = if p % l.align() == 0 {
            let n = l.pad_to_align().size();
            let (q, r) = num::integer::div_rem(n, p);
            if r == 0 {
                ((2 + q)*p, p)
            } else {
                ((2 + 1 + q)*p, p + (p - r))
            }
        } else {
            todo!()
        };

        let base = unsafe { data.offset(-(offset as isize)) };
        Self { base, data, total_size }
    }

    pub fn free(&self) -> crate::Result<()> {
        unsafe {
            let r = libc::munmap(self.base as *mut libc::c_void, self.total_size);
            if r != 0 {
                return Err(crate::Error::os("mmap"));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[global_allocator]
    static ALLOC: GuardedAllocator = GuardedAllocator::new();

    use super::*;
    use rand::{random, thread_rng, Rng};

    fn do_sized_alloc_test(n: usize) -> crate::Result<()> {
        let a = GuardedAllocator::new();
        let p = a.alloc_unaligned(n)?;

        let bs = unsafe { core::slice::from_raw_parts_mut(p, n) };
        for i in 0..n {
            assert_eq!(bs[i], 0);
        }

        thread_rng().fill(bs);

        a.dealloc_unaligned(p, n)?;

        Ok(())
    }

    fn page_size_exponent() -> u32 {
        let mut p = 1; let mut k = 0;
        while p != page_size() {
            p *= 2; k += 1;
        }
        k as u32
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
            do_sized_alloc_test(random::<usize>() % 1024*1024)?
        }
        Ok(())
    }

    #[test]
    fn alignment() -> crate::Result<()> {
        for _ in 1..100 {
            let a = 2usize.pow(random::<u32>() % page_size_exponent() + 3);

            let mut n = 0;
            while n == 0 { n = random::<usize>() % 3*page_size(); }

            let l = Layout::from_size_align(n, a).unwrap();
            let al = GuardedAllocator::new();
            let p = al.alloc(l)?;
            assert_eq!((p as usize) % a, 0);
            al.dealloc(p, l)?;
        }

        Ok(())
    }

    #[test]
    fn zero_allocation() -> crate::Result<()> {
        assert_eq!(
            GuardedAllocator::new().alloc_unaligned(0),
            Err(Error::ZeroAllocation.into()),
        );
        Ok(())
    }

    #[test]
    fn vectors() -> crate::Result<()> {
        extern crate alloc;
        use alloc::vec::Vec;

        let mut bs: Vec<u8> = Vec::with_capacity(10);
        for _ in 1..100 {
            bs.push(random());
        }

        Ok(())
    }
}
