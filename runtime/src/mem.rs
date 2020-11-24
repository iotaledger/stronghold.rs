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

fn pad(x: usize, n: usize) -> usize {
    match x % n {
        0 => 0,
        r => n - r,
    }
}

fn pad_minimizer(a: usize, b: usize, c: usize) -> usize {
    match b % c {
        0 => 0,
        bc => if bc % a == 0 {
            c / a - bc / a
        } else {
            c / a - bc / a - 1
        }
    }
}

fn mmap(n: usize) -> crate::Result<*mut u8> {
    let x = unsafe {
        libc::mmap(
            ptr::null_mut::<u8>() as *mut libc::c_void,
            n,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1, 0)
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

pub struct Allocation {
    base: *mut u8,
    data: *mut u8,
    mmapped_size: usize, // NB size of the memory mapping (including guard pages)
}

impl Allocation {
    pub fn new(l: Layout) -> crate::Result<Self> {
        let n = l.size();
        if n == 0 {
            return Err(Error::ZeroAllocation.into());
        }

        let a = l.align();
        let p = page_size();

        if p % a == 0 {
            let mmapped_size = p + n + pad(n, p) + p;
            let base = mmap(mmapped_size)?;
            let i = pad_minimizer(a, n, p);
            let data = unsafe { base.offset((p + i * a) as isize) };
            Ok(Self { base, data, mmapped_size })
        } else if a % p == 0 {
            let x = mmap(a + n + pad(n, p) + p)?;
            let i = a / p;
            let j = x as usize / p;
            let o = i - 1 - (j % i);
            let base = unsafe { x.offset((o * p) as isize) };
            if o > 0 {
                munmap(x, o * p)?;
            }
            let data = unsafe { base.offset(p as isize) };
            let mmapped_size = p + n + pad(n, p) + p;

            if j % i > 0 {
                let end = unsafe { base.offset(mmapped_size as isize) };
                munmap(end, (j % i) * p)?;
            }

            Ok(Self { base, data, mmapped_size })
        } else {
            Err(crate::Error::unreachable("page size and requested alignment is coprime"))
        }

        // TODO: write canary for the writable page (NB don't write canaries in the guards,
        // then at least they don't reserve physical memory, (assuming COW))
        // TODO: lock the guard pages
        // TODO: mlock the data pages
        // TODO: zero the data pages
    }

    pub fn from_ptr(data: *mut u8, l: Layout) -> Self {
        let p = page_size();
        let n = l.size();
        let base = unsafe { data.offset(-((p + (data as usize) % p) as isize)) };
        let mmapped_size = p + n + pad(n, p) + p;
        Self { base, data, mmapped_size }
    }

    pub fn free(&self) -> crate::Result<()> {
        munmap(self.base, self.mmapped_size)
    }
}

#[cfg(test)]
mod tests {
    #[global_allocator]
    static ALLOC: GuardedAllocator = GuardedAllocator::new();

    use super::*;
    use rand::{random, thread_rng, Rng};

    fn page_size_exponent() -> u32 {
        let mut p = 1; let mut k = 0;
        while p != page_size() {
            p *= 2; k += 1;
        }
        k as u32
    }

    fn fresh_layout() -> Layout {
        let mut n = 0;
        while n == 0 { n = random::<usize>() % 3*page_size(); }

        let a = 2usize.pow(random::<u32>() % page_size_exponent() + 3);

        Layout::from_size_align(n, a).unwrap()
    }

    fn do_test_write(p: *mut u8, n: usize) {
        let bs = unsafe { core::slice::from_raw_parts_mut(p, n) };
        for i in 0..n {
            assert_eq!(bs[i], 0);
        }

        thread_rng().fill(bs);
    }

    fn do_sized_alloc_test(n: usize) -> crate::Result<()> {
        let a = GuardedAllocator::new();
        let p = a.alloc_unaligned(n)?;

        do_test_write(p, n);

        a.dealloc_unaligned(p, n)?;

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
            do_sized_alloc_test(random::<usize>() % 1024*1024)?
        }
        Ok(())
    }

    #[test]
    fn alignment() -> crate::Result<()> {
        for _ in 1..100 {
            let l = fresh_layout();
            let al = GuardedAllocator::new();
            let p = al.alloc(l)?;
            assert_eq!((p as usize) % l.align(), 0);
            do_test_write(p, l.size());

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

    #[test]
    fn inside_zone() -> crate::Result<()> {
        let l = fresh_layout();
        crate::zone::soft(|| {
            let s = crate::seccomp::Spec {
                anonymous_mmap: true,
                munmap: true,
                ..crate::seccomp::Spec::default()
            };
            s.apply().unwrap();

            let al = GuardedAllocator::new();
            let p = al.alloc(l).unwrap();
            al.dealloc(p, l).unwrap();
            unsafe { libc::_exit(0); }
        })
    }
}
