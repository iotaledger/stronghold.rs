use crate::types::*;

use libsodium_sys::sodium_memcmp;

pub trait ConstEq: ContiguousBytes {
    fn const_eq(&self, rhs: &Self) -> bool {
        unsafe {
            sodium_memcmp(
                self.as_bytes().as_ptr() as *const _,
                rhs.as_bytes().as_ptr() as *const _,
                rhs.as_bytes().len(),
            ) == 0
        }
    }
}

impl<T: ContiguousBytes> ConstEq for T {}
impl<T: Bytes> ConstEq for [T] {}
