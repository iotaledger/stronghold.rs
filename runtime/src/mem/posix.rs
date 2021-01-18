use core::{
    alloc::{GlobalAlloc, Layout, LayoutErr},
    cell::Cell,
    marker::PhantomData,
    ops::{Deref, DerefMut},
    ptr,
};

use crate::secret::{ Protection};

use zeroize::Zeroize;

use super::{pad, pad_minimizer, Error, GuardedBox};

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
        assert_eq!(*gb.access(), 7);
        *gb.access() = 8;
        assert_eq!(*gb.access(), 8);
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
