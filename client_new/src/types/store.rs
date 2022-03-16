// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

pub struct Store<K, V> {
    key: K,
    value: V,
}

impl<K, V> Store<K, V> {
    /// Inserts a value into the store
    pub async fn insert(&self, key: K, value: V) {}

    ///
    pub async fn get(&self, key: &K) -> Option<&V> {
        todo!()
    }

    pub async fn delete(&self, key: &K) -> Result<V, Box<dyn Error>> {
        todo!()
    }
}
