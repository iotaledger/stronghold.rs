use libsodium_sys::{sodium_mlock, sodium_munlock};

pub(crate) unsafe fn mlock<T>(ptr: *mut T) -> bool {
    sodium_mlock(ptr as *mut _, core::mem::size_of::<T>()) == 0
}

pub(crate) unsafe fn munlock<T>(ptr: *mut T) -> bool {
    sodium_munlock(ptr as *mut _, core::mem::size_of::<T>()) == 0
}
