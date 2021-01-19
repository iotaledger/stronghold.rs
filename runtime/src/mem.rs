// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

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

    pub fn protect(&self, read: bool, write: bool) -> crate::Result<()> {
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

#[cfg(feature = "stdalloc")]
pub mod stdalloc {
    use super::*;
    use core::cell::Cell;

    struct Toggleable<A, B> {
        a: A,
        b: B,
    }

    impl<A, B> Toggleable<A, B> {
        const fn new(a: A, b: B) -> Self {
            Self { a, b }
        }
    }

    unsafe impl<A: GlobalAlloc, B: GlobalAlloc> GlobalAlloc for Toggleable<A, B> {
        unsafe fn alloc(&self, l: Layout) -> *mut u8 {
            T.with(|t| match t.get() {
                false => self.a.alloc(l),
                true => self.b.alloc(l),
            })
        }

        unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
            T.with(|t| match t.get() {
                false => self.a.dealloc(p, l),
                true => self.b.dealloc(p, l),
            })
        }
    }

    thread_local! {
        static T: Cell<bool> = Cell::new(false);
    }

    #[global_allocator]
    static ALLOC: Toggleable<std::alloc::System, GuardedAllocator> =
        Toggleable::new(std::alloc::System, GuardedAllocator::new());

    /// Use the standad allocator from this point on in the current thread
    ///
    /// # Safety
    /// If the allocator used to allocate memory is not enabled when deallocation occurs the
    /// behavior is undefined. Hopefully the process will get killed with a SIGSEGV. It is
    /// recommended to switch allocators early and late in a process'/thread's lifetime.
    pub unsafe fn std() {
        T.with(|t| t.set(false));
    }

    /// Use the guarded allocator from this point on in the current thread
    ///
    /// # Safety
    /// If the allocator used to allocate memory is not enabled when deallocation occurs the
    /// behavior is undefined. Hopefully the process will get killed with a SIGSEGV. It is
    /// recommended to switch allocators early and late in a process'/thread's lifetime.
    pub unsafe fn guarded() {
        T.with(|t| t.set(true));
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
    use super::*;
    use rand::{rngs::OsRng, Rng};

    #[cfg(target_os = "linux")]
    const MEM_ACCESS_ERR: crate::Error = crate::Error::ZoneError(crate::zone::Error::Signal { signo: libc::SIGSEGV });
    #[cfg(target_os = "macos")]
    const MEM_ACCESS_ERR: crate::Error = crate::Error::ZoneError(crate::zone::Error::Signal { signo: libc::SIGBUS });

    #[cfg(not(feature = "stdalloc"))]
    #[global_allocator]
    static ALLOC: GuardedAllocator = GuardedAllocator::new();

    #[cfg(not(feature = "stdalloc"))]
    fn with_guarded_allocator<A, F: FnOnce() -> A>(f: F) -> A {
        f()
    }

    #[cfg(feature = "stdalloc")]
    fn with_guarded_allocator<A, F: FnOnce() -> A>(f: F) -> A {
        unsafe { stdalloc::guarded() };
        let a = f();
        unsafe { stdalloc::std() };
        a
    }

    fn page_size_exponent() -> u32 {
        let mut p = 1;
        let mut k = 0;
        while p != page_size() {
            p *= 2;
            k += 1;
        }
        k as u32
    }

    fn fresh_non_zero_size(bound: usize) -> usize {
        let mut n = 0;
        while n == 0 {
            n = OsRng.gen::<usize>() % bound;
        }
        n
    }

    fn fresh_layout() -> Layout {
        let n = fresh_non_zero_size(3 * page_size());
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
            do_sized_alloc_test(fresh_non_zero_size(1024 * 1024))?
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
            crate::zone::fork(|| {
                for i in 0..page_size() {
                    unsafe {
                        assert_eq!(0u8, core::ptr::read_unaligned(a.data().offset(-(i as isize))));
                    }
                }
            }),
            Err(MEM_ACCESS_ERR)
        );

        Ok(())
    }

    #[test]
    fn guard_pages_pre_write() -> crate::Result<()> {
        let l = fresh_layout();
        let a = GuardedAllocation::aligned(l)?;

        assert_eq!(
            crate::zone::fork(|| {
                for i in 0..page_size() {
                    unsafe {
                        core::ptr::write_unaligned(a.data().offset(-(i as isize)), OsRng.gen());
                    }
                }
            }),
            Err(MEM_ACCESS_ERR)
        );

        Ok(())
    }

    #[test]
    fn guard_pages_post_read() -> crate::Result<()> {
        let l = fresh_layout();
        let a = GuardedAllocation::aligned(l)?;

        assert_eq!(
            crate::zone::fork(|| {
                for i in 0..page_size() {
                    unsafe {
                        assert_eq!(0u8, core::ptr::read_unaligned(a.data().add(l.size() + i)));
                    };
                }
            }),
            Err(MEM_ACCESS_ERR)
        );

        Ok(())
    }

    #[test]
    fn guard_pages_post_write() -> crate::Result<()> {
        let l = fresh_layout();
        let a = GuardedAllocation::aligned(l)?;

        assert_eq!(
            crate::zone::fork(|| {
                for i in 0..page_size() {
                    unsafe {
                        core::ptr::write_unaligned(a.data().add(l.size() + i), OsRng.gen());
                    }
                }
            }),
            Err(MEM_ACCESS_ERR)
        );

        Ok(())
    }

    #[test]
    fn vectors() -> crate::Result<()> {
        with_guarded_allocator(|| {
            extern crate alloc;
            use alloc::vec::Vec;

            let mut bs: Vec<u8> = Vec::with_capacity(10);
            for _ in 1..100 {
                bs.push(OsRng.gen());
            }

            Ok(())
        })
    }

    // TODO: unify these apis, maybe a dedicated zone::Spec?
    #[test]
    #[cfg(target_os = "linux")]
    fn inside_zone_linux() -> crate::Result<()> {
        let l = fresh_layout();
        crate::zone::fork(|| {
            seccomp_spec().with_getrandom().apply().unwrap();
            let a = GuardedAllocation::aligned(l).unwrap();
            do_test_write(a.data(), l.size());
            a.free().unwrap();
        })
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn inside_zone_macos() -> crate::Result<()> {
        let l = fresh_layout();
        crate::zone::fork(|| {
            let a = GuardedAllocation::aligned(l).unwrap();
            do_test_write(a.data(), l.size());
            a.free().unwrap();
        })
    }
}
