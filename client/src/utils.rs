// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod ids;
mod types;

use std::{collections::HashMap, hash::Hash};

// use engine::vault::{RecordId, VaultId};
// use serde::{Deserialize, Serialize};

pub use self::{
    ids::LoadFromPath,
    types::{EntryShape, Location, StrongholdFlags, VaultFlags},
};

/// Gets the index of a slice.
#[allow(dead_code)]
pub fn index_of_unchecked<T>(slice: &[T], item: &T) -> usize {
    if ::std::mem::size_of::<T>() == 0 {
        return 0;
    }
    (item as *const _ as usize - slice.as_ptr() as usize) / std::mem::size_of::<T>()
}

/// Converts a [`Vec`] consisting of tuples of generic `K` and `V`
/// into a [`HashMap`]
pub fn into_map<K, V>(v: Vec<(K, V)>) -> HashMap<K, V>
where
    K: Hash + Eq,
{
    let mut map = HashMap::new();
    v.into_iter().for_each(|(k, v)| {
        map.insert(k, v);
    });
    map
}

/// Returns the complement items from A not in B
pub fn complement<T>(a: Vec<T>, b: Vec<T>) -> Vec<T>
where
    T: PartialEq + Clone,
{
    a.into_iter().filter(|item| !b.contains(item)).collect()
}
