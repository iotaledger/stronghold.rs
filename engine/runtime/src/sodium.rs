// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use libsodium_sys::{sodium_mlock, sodium_munlock};

/// A wrapper around the [`sodium_mlock`] function.
pub(crate) unsafe fn mlock<T>(ptr: *mut T) -> bool {
    sodium_mlock(ptr as *mut _, core::mem::size_of::<T>()) == 0
}

/// A wrapper around the [`sodium_munlock`] function.
pub(crate) unsafe fn munlock<T>(ptr: *mut T) -> bool {
    sodium_munlock(ptr as *mut _, core::mem::size_of::<T>()) == 0
}
