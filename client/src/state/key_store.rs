// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use engine::vault::{BoxProvider, Key, VaultId};

use std::collections::HashMap;

use crate::line_error;

pub struct KeyStore<P: BoxProvider + Clone + Send + Sync + 'static> {
    store: HashMap<VaultId, Key<P>>,
}

impl<P: BoxProvider + Clone + Send + Sync + 'static> KeyStore<P> {
    /// Creates a new `KeyStore`.
    pub fn new() -> Self {
        Self { store: HashMap::new() }
    }

    /// Gets the key from the `KeyStore` and removes it.  Returns an `Option<Key<P>>`
    pub fn get_key(&mut self, id: VaultId) -> Option<Key<P>> {
        self.store.remove(&id)
    }

    pub fn vault_exists(&self, id: VaultId) -> bool {
        self.store.contains_key(&id)
    }

    /// Returns an existing key for the `id` or creates one.
    pub fn create_key(&mut self, id: VaultId) -> Key<P> {
        let key = self
            .store
            .entry(id)
            .or_insert_with(|| Key::<P>::random().expect(line_error!()));

        key.clone()
    }

    /// Inserts a key into the `KeyStore` by `VaultId`.  If the `VaultId` already exists, it just returns the existing
    /// `&Key<P>`
    pub fn insert_key(&mut self, id: VaultId, key: Key<P>) -> &Key<P> {
        self.store.entry(id).or_insert(key)
    }

    /// Rebuilds the `KeyStore` while throwing out any existing `VauldId`, `Key<P>` pairs.  Accepts a `Vec<Key<P>>` and
    /// returns the a `Vec<VaultId>` containing all of the new `VaultId`s
    pub fn rebuild_keystore(&mut self, keys: HashMap<VaultId, Key<P>>) {
        self.store = keys;
    }

    pub fn get_data(&mut self) -> HashMap<VaultId, Key<P>> {
        let mut key_store: HashMap<VaultId, Key<P>> = HashMap::new();

        self.store.iter().for_each(|(v, k)| {
            key_store.insert(*v, k.clone());
        });

        key_store
    }

    pub fn clear_keys(&mut self) {
        self.store.clear();
    }
}
