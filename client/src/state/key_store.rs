// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use engine::vault::{Key, VaultId};
use std::collections::HashMap;

use crate::Provider;

pub struct KeyStore {
    store: HashMap<VaultId, Key<Provider>>,
}

impl KeyStore {
    /// Creates a new [`KeyStore`].
    pub fn new() -> Self {
        Self { store: HashMap::new() }
    }

    /// Gets the key from the [`KeyStore`] without removing it.
    pub fn get_key(&self, id: VaultId) -> Option<&Key<Provider>> {
        self.store.get(&id)
    }

    /// Gets the key from the [`KeyStore`] and removes it.
    pub fn take_key(&mut self, id: VaultId) -> Option<Key<Provider>> {
        self.store.remove(&id)
    }

    /// Checks to see if the vault exists.
    pub fn vault_exists(&self, id: VaultId) -> bool {
        self.store.contains_key(&id)
    }

    /// Returns an existing key for the `id` or creates one.
    pub fn create_key(&mut self, id: VaultId) -> &Key<Provider> {
        self.store.entry(id).or_insert_with(Key::random)
    }

    /// Inserts a key into the [`KeyStore`] by [`VaultId`].  If the [`VaultId`] already exists, it just returns the
    /// existing &[`Key<Provider>`]
    pub fn entry_or_insert_key(&mut self, id: VaultId, key: Key<Provider>) -> &Key<Provider> {
        self.store.entry(id).or_insert(key)
    }

    /// Rebuilds the [`KeyStore`] while throwing out any existing [`VaultId`], [`Key<Provider>`] pairs.  Accepts a
    /// [`Vec<Key<Provider>>`] and returns then a [`Vec<VaultId>`]; primarily used to repopulate the state from a
    /// snapshot.
    pub fn rebuild_keystore(&mut self, keys: HashMap<VaultId, Key<Provider>>) {
        self.store = keys;
    }

    /// Gets the state data in a hashmap format for the snapshot.
    pub fn get_data(&mut self) -> HashMap<VaultId, Key<Provider>> {
        let mut key_store: HashMap<VaultId, Key<Provider>> = HashMap::new();

        self.store.iter().for_each(|(v, k)| {
            key_store.insert(*v, k.clone());
        });

        key_store
    }

    /// Clear the key store.
    pub fn clear_keys(&mut self) {
        self.store.clear();
    }
}
