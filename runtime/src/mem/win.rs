use core::mem;
use core::ptr::{self, NonNull};

extern crate std;

use self::std::alloc::{alloc, dealloc, Layout};
use self::std::process::abort;
use self::std::sync::Once;
use getrandom::getrandom;

use winapi::{
    shared::{
        basetsd::SIZE_T,
        minwindef::{DWORD, LPVOID},
    },
    um::memoryapi::{VirtualLock, VirtualProtect, VirtualUnlock},
    um::sysinfoapi::{GetSystemInfo, SYSTEM_INFO},
    um::winnt,
};

pub const GARBAGE_VALUE: u8 = 0xd0;
pub const CANARY_SIZE: usize = 16;
pub static mut PAGE_SIZE: usize = 0;
pub static mut PAGE_MASK: usize = 0;
pub static ALLOC_INIT: Once = Once::new();
pub static mut CANARY: [u8; CANARY_SIZE] = [0; CANARY_SIZE];

pub const PROT_NONE: u32 = winnt::PAGE_NOACCESS;
pub const PROT_READ: u32 = winnt::PAGE_READONLY;
pub const PROT_WRITE: u32 = winnt::PAGE_READWRITE;
pub const PROT_READ_WRITE: u32 = winnt::PAGE_READWRITE;

pub fn lock(addr: *mut u8, len: usize) -> bool {
    unsafe { VirtualLock(addr as LPVOID, len as usize) != 0 }
}

pub unsafe fn unlock(addr: *mut u8, len: usize) -> bool {
    memzero(addr, len);
    VirtualUnlock(addr as LPVOID, len as usize) != 0
}

#[inline(never)]
pub unsafe fn memeq(b1: *const u8, b2: *const u8, len: usize) -> bool {
    (0..len)
        .map(|i| ptr::read_volatile(b1.add(i)) ^ ptr::read_volatile(b2.add(i)))
        .fold(0, |sum, next| sum | next)
        .eq(&0)
}

#[inline(never)]
pub unsafe fn memcmp(b1: *const u8, b2: *const u8, len: usize) -> i32 {
    let mut res = 0;
    for i in (0..len).rev() {
        let diff = i32::from(ptr::read_volatile(b1.add(i))) - i32::from(ptr::read_volatile(b2.add(i)));
        res = (res & (((diff - 1) & !diff) >> 8)) | diff;
    }
    ((res - 1) >> 8) + (res >> 8) + 1
}

#[inline(never)]
pub unsafe fn memset(s: *mut u8, c: u8, n: usize) {
    let s = ptr::read_volatile(&s);
    let c = ptr::read_volatile(&c);
    let n = ptr::read_volatile(&n);

    for i in 0..n {
        ptr::write(s.add(i), c);
    }

    let _ = ptr::read_volatile(&s);
}

#[inline]
pub unsafe fn memzero(dest: *mut u8, n: usize) {
    memset(dest, 0, n);
}

#[inline]
unsafe fn alloc_init() {
    let mut si = mem::MaybeUninit::uninit();
    winapi::um::sysinfoapi::GetSystemInfo(si.as_mut_ptr());
    PAGE_SIZE = (*si.as_ptr()).dwPageSize as usize;

    if PAGE_SIZE < CANARY_SIZE || PAGE_SIZE < mem::size_of::<usize>() {
        panic!("page size too small");
    }

    PAGE_MASK = PAGE_SIZE - 1;

    getrandom(&mut CANARY).unwrap();
}

pub fn protect<T: ?Sized>(memptr: NonNull<T>, prot: u32) -> bool {
    unsafe {
        let memptr = memptr.as_ptr() as *mut u8;

        let unprod_ptr = unprotected_ptr_from_ptr(memptr);
        let base_ptr = unprod_ptr.sub(PAGE_SIZE * 2);
        let unprotected_size = ptr::read(base_ptr as *const usize);
        vprotect(unprod_ptr, unprotected_size, prot)
    }
}

#[inline]
pub unsafe fn vprotect(ptr: *mut u8, len: usize, prot: u32) -> bool {
    let mut old = mem::MaybeUninit::<DWORD>::uninit();

    VirtualProtect(ptr as LPVOID, len as SIZE_T, prot as DWORD, old.as_mut_ptr()) != 0
}

pub fn munmap<T: ?Sized>(memptr: NonNull<T>) {
    unsafe {
        let memptr = memptr.as_ptr() as *mut u8;

        let canary_ptr = memptr.sub(CANARY_SIZE);
        let unprotected_ptr = unprotected_ptr_from_ptr(memptr);
        let base_ptr = unprotected_ptr.sub(PAGE_SIZE * 2);
        let unprotected_size = ptr::read(base_ptr as *const usize);

        if !memeq(canary_ptr as *const u8, CANARY.as_ptr(), CANARY_SIZE) {
            abort();
        }

        let total_size = PAGE_SIZE + PAGE_SIZE + unprotected_size + PAGE_SIZE;
        vprotect(base_ptr, total_size, PROT_READ);

        unlock(unprotected_ptr, unprotected_size);

        munmap_aligned(base_ptr, total_size);
    }
}

pub fn mmap(size: usize) -> Option<(*mut u8, *mut u8, *mut u8)> {
    unsafe {
        ALLOC_INIT.call_once(|| alloc_init());

        if size >= ::core::usize::MAX - PAGE_SIZE * 4 {
            return None;
        }

        let size_with_canary = CANARY_SIZE + size;
        let unprotected_size = page_round(size_with_canary);
        let total_size = PAGE_SIZE + PAGE_SIZE + unprotected_size + PAGE_SIZE;
        let base_ptr = alloc_aligned(total_size)?.as_ptr();
        let unprotected_ptr = base_ptr.add(PAGE_SIZE * 2);

        vprotect(base_ptr.add(PAGE_SIZE), PAGE_SIZE, PROT_NONE);
        vprotect(unprotected_ptr.add(unprotected_size), PAGE_SIZE, PROT_NONE);

        let canary_ptr = unprotected_ptr.add(unprotected_size - size_with_canary);
        let user_ptr = canary_ptr.add(CANARY_SIZE);
        ptr::copy_nonoverlapping(CANARY.as_ptr(), canary_ptr, CANARY_SIZE);
        ptr::write_unaligned(base_ptr as *mut usize, unprotected_size);
        vprotect(base_ptr, PAGE_SIZE, PROT_READ);

        assert_eq!(unprotected_ptr_from_ptr(user_ptr), unprotected_ptr);

        Some((base_ptr as *mut u8, user_ptr as *mut u8, unprotected_ptr as *mut u8))
    }
}

pub fn calc_total_size(size: usize) -> usize {
    unsafe { PAGE_SIZE + PAGE_SIZE + page_round(CANARY_SIZE + size) + PAGE_SIZE }
}

#[inline]
pub fn page_round(size: usize) -> usize {
    unsafe { (size + PAGE_MASK) & !PAGE_MASK }
}

#[inline]
pub unsafe fn unprotected_ptr_from_ptr(memptr: *const u8) -> *mut u8 {
    let canary_ptr = memptr.sub(CANARY_SIZE);
    let unprotected_ptr_u = canary_ptr as usize & !PAGE_MASK;

    unprotected_ptr_u as *mut u8
}

#[inline]
pub unsafe fn alloc_aligned(size: usize) -> Option<NonNull<u8>> {
    let layout = Layout::from_size_align_unchecked(size, PAGE_SIZE);
    NonNull::new(alloc(layout))
}

#[inline]
pub unsafe fn munmap_aligned(memptr: *mut u8, size: usize) {
    memzero(memptr, size);
    let layout = Layout::from_size_align_unchecked(size, PAGE_SIZE);
    dealloc(memptr, layout);
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
