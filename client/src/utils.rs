// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod ask;
#[allow(non_snake_case, dead_code)]
pub mod hd;
mod ids;
mod types;

pub use self::{
    ask::ask,
    hd::{Chain, Key, Seed, Segment},
    ids::{ClientId, LoadFromPath, VaultId},
    types::{ResultMessage, StatusMessage, StrongholdFlags, VaultFlags},
};

#[allow(dead_code)]
pub fn index_of_unchecked<T>(slice: &[T], item: &T) -> usize {
    if ::std::mem::size_of::<T>() == 0 {
        return 0;
    }
    (item as *const _ as usize - slice.as_ptr() as usize) / std::mem::size_of::<T>()
}
