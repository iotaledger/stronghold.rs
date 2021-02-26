use crate::types::*;

use libsodium_sys::randombytes_buf;

pub unsafe trait Randomized: ContiguousBytes {
    fn randomize(&mut self) {
        unsafe { randombytes_buf(self.as_mut_bytes().as_mut_ptr() as *mut _, self.as_bytes().len()) }
    }
}

unsafe impl<T: ContiguousBytes + ?Sized> Randomized for T {}
