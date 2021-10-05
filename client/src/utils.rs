// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod ids;
mod types;

pub use self::{
    ids::LoadFromPath,
    types::{Location, LocationError, ResultMessage, StatusMessage, StrongholdFlags, VaultFlags},
};

/// Gets the index of a slice.
#[allow(dead_code)]
pub fn index_of_unchecked<T>(slice: &[T], item: &T) -> usize {
    if ::std::mem::size_of::<T>() == 0 {
        return 0;
    }
    (item as *const _ as usize - slice.as_ptr() as usize) / std::mem::size_of::<T>()
}
