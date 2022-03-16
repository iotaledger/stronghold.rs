// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

use crate::Cache;

pub struct Store {
    cache: Cache<Vec<u8>, Vec<u8>>,
}

impl Store {
    /// Inserts a value into the store
    pub async fn insert(&self, key: Vec<u8>, value: Vec<u8>) {
        todo!()
    }

    ///
    pub async fn get(&self, key: Vec<u8>) -> Option<&Vec<u8>> {
        todo!()
    }

    pub async fn delete(&self, key: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
        todo!()
    }
}
