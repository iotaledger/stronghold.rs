use core::{
    alloc::{GlobalAlloc, Layout},
    ptr,
};

use super::{Error, GuardedAllocation};

lazy_static! {
    pub static ref PAGE_SIZE: usize = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
}

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

pub fn prot(read: bool, write: bool) -> i32 {
    (read as i32 * libc::PROT_READ) | (write as i32 * libc::PROT_WRITE)
}

pub fn lock(data_region_start: *mut u8, data_region_size: usize) -> crate::Result<()> {
    match unsafe { libc::mlock(data_region_start as *mut libc::c_void, data_region_size) } {
        0 => Ok(()),
        _ => Err(crate::Error::os("mlock")),
    }
}
