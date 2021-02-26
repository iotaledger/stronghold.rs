use crate::types::*;

use libsodium_sys::sodium_memzero;

pub unsafe trait ZeroOut: ContiguousBytes {
    fn zero(&mut self) {
        unsafe { sodium_memzero(self.as_mut_bytes().as_mut_ptr() as *mut _, self.as_bytes().len()) }
    }

    unsafe fn copy_and_zero(&mut self, other: &mut Self) {
        assert!(other.size() >= self.size(), "other must be larger than self");

        assert!(
            (self.as_u8_ptr() < other.as_u8_ptr() && self.as_u8_ptr().add(self.size()) <= other.as_u8_ptr())
                || (other.as_u8_ptr() < self.as_u8_ptr() && other.as_u8_ptr().add(other.size()) <= self.as_u8_ptr()),
            "Pointers for the secrets must not overlap"
        );

        self.as_mut_u8_ptr()
            .copy_to_nonoverlapping(other.as_mut_u8_ptr(), self.size());

        self.zero()
    }
}

unsafe impl<T: ContiguousBytes + ?Sized> ZeroOut for T {}
