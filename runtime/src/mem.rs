// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::{
    alloc::{GlobalAlloc, Layout},
    ptr,
};

#[derive(PartialEq, Debug)]
pub enum Error {
    ZeroAllocation,
}

#[cfg(unix)]
fn page_size() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

pub struct GuardedAllocator {
    page_size: usize,
}

impl GuardedAllocator {
    pub fn new() -> Self {
        Self {
            page_size: page_size(),
        }
    }

    pub fn alloc(&self, n: usize) -> crate::Result<*mut u8> {
        if n == 0 {
            return Err(crate::Error::MemError(Error::ZeroAllocation));
        }

        let (size, offset) = if n % self.page_size == 0 {
            (2*self.page_size + n, self.page_size)
        } else {
            let (q, r) = num::integer::div_rem(n, self.page_size);
            ((2 + q)*self.page_size, self.page_size + r)
        };

        unsafe {
            let base = libc::mmap(
                ptr::null_mut::<u8>() as *mut libc::c_void,
                size,
                libc::PROT_NONE,
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

    pub fn dealloc(&self, _p: *mut u8) -> crate::Result<()> {
        // TODO: verify the canary
        // TODO: zero the data pages
        // TODO: munmap
        todo!()
    }
}

unsafe impl GlobalAlloc for GuardedAllocator {
    unsafe fn alloc(&self, _: Layout) -> *mut u8 { todo!() }
    unsafe fn dealloc(&self, _: *mut u8, _: Layout) { todo!() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocate_whole_page() -> crate::Result<()> {
        let _ = GuardedAllocator::new().alloc(page_size())?;
        Ok(())
    }

    #[test]
    fn allocate_less_than_a_whole_page() -> crate::Result<()> {
        let _ = GuardedAllocator::new().alloc(1)?;
        Ok(())
    }

    #[test]
    fn zero_allocation() -> crate::Result<()> {
        assert_eq!(
            GuardedAllocator::new().alloc(0),
            Err(crate::Error::MemError(Error::ZeroAllocation)),
        );
        Ok(())
    }
}
