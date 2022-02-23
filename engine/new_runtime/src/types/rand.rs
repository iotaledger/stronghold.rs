// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::types::*;

use libsodium_sys::randombytes_buf;

/// A trait for generating random bytes via [`randombytes_buf`].
pub unsafe trait Randomized: ContiguousBytes {
    fn randomize(&mut self) {
        unsafe { randombytes_buf(self.as_mut_bytes().as_mut_ptr() as *mut _, self.as_bytes().len()) }
    }
}

unsafe impl<T: ContiguousBytes + ?Sized> Randomized for T {}
