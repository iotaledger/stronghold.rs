use core::ptr;
use winapi::um::winnt;
use winapi::{
    shared::minwindef::{DWORD, LPVOID},
    um::{
        memoryapi::{VirtualAlloc, VirtualFree, VirtualLock, VirtualProtect},
        sysinfoapi::{GetSystemInfo, SYSTEM_INFO},
        winnt::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_NOACCESS},
    },
};
pub const PROT_NONE: u32 = winnt::PAGE_NOACCESS;
pub const PROT_READ: u32 = winnt::PAGE_READONLY;
pub const PROT_WRITE: u32 = winnt::PAGE_READWRITE;
pub const PROT_READ_WRITE: u32 = winnt::PAGE_READWRITE;

pub fn mmap(size: usize) -> crate::Result<*mut u8> {
    unsafe {
        let ptr = VirtualAlloc(ptr::null_mut(), size as usize, MEM_RESERVE | MEM_COMMIT, PAGE_NOACCESS) as *mut u8;

        if ptr.is_null() {
            Err(crate::Error::os("mmap"))
        } else {
            Ok(ptr as *mut u8)
        }
    }
}

pub fn munmap(ptr: *mut u8, _n: usize) -> crate::Result<()> {
    let ret = unsafe { VirtualFree(ptr as *mut _, 0, MEM_RELEASE) };

    match ret {
        0 => Ok(()),
        _ => Err(crate::Error::os("munmap")),
    }
}

pub fn protect(ptr: *mut u8, size: usize, prots: u32) -> crate::Result<()> {
    let mut _old_prot: DWORD = 0;

    #[cfg(target_pointer_width = "64")]
    type U = u64;
    #[cfg(target_pointer_width = "32")]
    type U = u32;

    let ret = unsafe { VirtualProtect(ptr as *mut _, size as usize, prots, &mut _old_prot as *mut _) };

    match ret {
        0 => Ok(()),
        _ => Err(crate::Error::os("protect")),
    }
}

pub fn lock(addr: *mut u8, len: usize) -> crate::Result<()> {
    let ret = unsafe { VirtualLock(addr as LPVOID, len as usize) };

    match ret {
        0 => Ok(()),
        _ => Err(crate::Error::os("lock")),
    }
}

pub fn prot(read: bool, write: bool) -> u32 {
    match (read, write) {
        (false, false) => PROT_NONE,
        (true, false) => PROT_READ,
        (false, true) => PROT_WRITE,
        (true, true) => PROT_READ_WRITE,
    }
}

pub fn page_size() -> usize {
    unsafe {
        let mut info = core::mem::MaybeUninit::<SYSTEM_INFO>::uninit();
        GetSystemInfo(info.as_mut_ptr());

        info.assume_init().dwPageSize as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_page_size() {
        println!("{:?}", page_size());
    }
}
