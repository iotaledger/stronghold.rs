// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

extern crate alloc;

use core::{
    mem::{self, MaybeUninit},
    slice,
};

use alloc::vec::Vec;

use vault::{BoxProvider, Key, ReadResult};

const GARBAGE_VALUE: u8 = 0xdb;

pub unsafe trait Bytes: Sized + Clone {
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

unsafe impl<T: BoxProvider> Bytes for Key<T> {}
unsafe impl Bytes for ReadResult {}
unsafe impl Bytes for Vec<ReadResult> {}
