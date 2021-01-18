use core::{
    alloc::{GlobalAlloc, Layout, LayoutErr},
    cell::Cell,
    marker::PhantomData,
    ops::{Deref, DerefMut},
    ptr,
};

use crate::secret::{AccessSelf, Protection, ProtectionNew};

use zeroize::Zeroize;

use super::{pad, pad_minimizer, Error};

#[cfg(unix)]
lazy_static! {
    static ref PAGE_SIZE: usize = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
}
#[cfg(unix)]
pub fn page_size() -> usize {
    *PAGE_SIZE
}

pub fn mmap(n: usize) -> crate::Result<*mut u8> {
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

pub fn munmap(p: *mut u8, n: usize) -> crate::Result<()> {
    match unsafe { libc::munmap(p as *mut libc::c_void, n) } {
        0 => Ok(()),
        _ => Err(crate::Error::os("munmap")),
    }
}

pub fn protect(data_region_start: *mut u8, data_region_size: usize, prot: i32) -> crate::Result<()> {
    match unsafe { libc::mprotect(data_region_start as *mut libc::c_void, data_region_size, prot) } {
        0 => Ok(()),
        _ => Err(crate::Error::os("mprotect")),
    }
}

pub fn lock(data_region_start: *mut u8, data_region_size: usize) -> crate::Result<()> {
    match unsafe { libc::mlock(data_region_start as *mut libc::c_void, data_region_size) } {
        0 => Ok(()),
        _ => Err(crate::Error::os("mlock")),
    }
}

pub fn prot(read: bool, write: bool) -> i32 {
    (read as i32 * libc::PROT_READ) | (write as i32 * libc::PROT_WRITE)
}

#[cfg(test)]
mod guarded_box_tests {
    use super::*;

    #[test]
    fn read() -> crate::Result<()> {
        let gb = GuardedBox::new(7)?;
        assert_eq!(*gb.access()?, 7);
        *gb.access()? = 8;
        assert_eq!(*gb.access()?, 8);
        Ok(())
    }

    #[test]
    fn drop() -> crate::Result<()> {
        struct Droplet<'a> {
            dropped: &'a Cell<bool>,
        }

        impl Drop for Droplet<'_> {
            fn drop(&mut self) {
                self.dropped.set(true);
            }
        }

        let b = Cell::new(false);

        {
            let _gb = GuardedBox::new(Droplet { dropped: &b });
            assert_eq!(b.get(), false);
        }

        assert_eq!(b.get(), true);

        Ok(())
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
