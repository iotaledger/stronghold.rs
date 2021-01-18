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

