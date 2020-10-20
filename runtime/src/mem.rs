// Copyright 2020 IOTA Stiftung
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

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

    pub fn alloc(&self, n: usize) -> crate::Result<*mut u8> {
        self.alloc_aligned(Layout::from_size_align(n, 1).map_err(|e| Error::Layout(e))?)
    }

    pub fn dealloc(&self, p: *mut u8, n: usize) -> crate::Result<()> {
        self.dealloc_aligned(p, Layout::from_size_align(n, 1).map_err(|e| Error::Layout(e))?)
    }

    fn align_with_guards(n: usize) -> (usize, usize) {
        let (q, r) = num::integer::div_rem(n, page_size());
        if r == 0 {
            ((2 + q)*page_size(), page_size())
        } else {
            ((2 + 1 + q)*page_size(), page_size() + (page_size() - r))
        }
    }

    pub fn alloc_aligned(&self, l: Layout) -> crate::Result<*mut u8> {
        let n = l.pad_to_align().size();

        if n == 0 {
            return Err(Error::ZeroAllocation.into());
        }

        let (size, offset) = Self::align_with_guards(n);

        unsafe {
            let base = libc::mmap(
                ptr::null_mut::<u8>() as *mut libc::c_void,
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1, 0);
            if base == libc::MAP_FAILED {
                return Err(crate::Error::os("mmap"));
            }
            let base = base as *mut u8;

            // TODO: write canary for the writable page (NB don't write canaries in the guards,
            // then at least they don't reserve physical memory, (assuming COW))
            // TODO: lock the guard pages
            // TODO: mlock the data pages
            // TODO: zero the data pages

            Ok(base.offset(offset as isize))
        }
    }

    pub fn dealloc_aligned(&self, p: *mut u8, l: Layout) -> crate::Result<()> {
        // TODO: verify the canary
        // TODO: zero the data pages

        let n = l.pad_to_align().size();
        let (size, offset) = Self::align_with_guards(n);

        unsafe {
            let base = p.offset(-(offset as isize));
            let r = libc::munmap(base as *mut libc::c_void, size);
            if r != 0 {
                return Err(crate::Error::os("mmap"));
            }
        }

        Ok(())
    }
}

unsafe impl GlobalAlloc for GuardedAllocator {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        self.alloc_aligned(l).unwrap()
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        self.dealloc_aligned(p, l).unwrap()
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
        let p = a.alloc(n)?;

        let bs = unsafe { core::slice::from_raw_parts_mut(p, n) };
        for i in 0..n {
            assert_eq!(bs[i], 0);
        }

        thread_rng().fill(bs);

        a.dealloc(p, n)?;

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
            let p = GuardedAllocator::new().alloc_aligned(l)?;
            assert_eq!((p as usize) % a, 0);
        }

        Ok(())
    }

    #[test]
    fn zero_allocation() -> crate::Result<()> {
        assert_eq!(
            GuardedAllocator::new().alloc(0),
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
