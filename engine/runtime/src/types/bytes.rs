// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::{
    mem::{self, MaybeUninit},
    slice,
};

const GARBAGE_VALUE: u8 = 0xdb;

/// A trait for dealing with Bytes.  Used as the underlying type for the `Guarded` and `GuardedVec` types.  For a type
/// to be able to be placed in one of these values, it must implement this trait.
///
/// # Safety
/// - todo
pub unsafe trait Bytes: Sized + Copy {
    fn uninitialized() -> Self {
        let mut val = MaybeUninit::<Self>::uninit();

        unsafe {
            val.as_mut_ptr().write_bytes(GARBAGE_VALUE, 1);
            val.assume_init()
        }
    }

    fn size() -> usize {
        mem::size_of::<Self>()
    }

    #[allow(trivial_casts)]
    fn as_u8_ptr(&self) -> *const u8 {
        self as *const Self as *const _
    }

    #[allow(trivial_casts)]
    fn as_mut_u8_ptr(&mut self) -> *mut u8 {
        self as *mut Self as *mut _
    }
}

/// # Safety
/// - todo
pub unsafe trait ContiguousBytes {
    fn size(&self) -> usize;
    fn as_u8_ptr(&self) -> *const u8;
    fn as_mut_u8_ptr(&mut self) -> *mut u8;
    fn as_bytes(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.as_u8_ptr(), self.size()) }
    }

    fn as_mut_bytes(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.as_mut_u8_ptr(), self.size()) }
    }
}

unsafe impl<T: Bytes> ContiguousBytes for T {
    fn size(&self) -> usize {
        Self::size()
    }

    fn as_u8_ptr(&self) -> *const u8 {
        self.as_u8_ptr()
    }

    fn as_mut_u8_ptr(&mut self) -> *mut u8 {
        self.as_mut_u8_ptr()
    }
}

unsafe impl<T: Bytes> ContiguousBytes for [T] {
    fn size(&self) -> usize {
        self.len() * T::size()
    }

    fn as_u8_ptr(&self) -> *const u8 {
        self.as_ptr() as *const _
    }

    fn as_mut_u8_ptr(&mut self) -> *mut u8 {
        self.as_ptr() as *mut _
    }
}
