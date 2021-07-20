// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::types::*;

use libsodium_sys::sodium_memcmp;

/// A trait for comparing types in Constant Time using [`sodium_memcmp`].
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
