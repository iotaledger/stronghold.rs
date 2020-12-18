// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use engine::vault::{BoxProvider, Key};

use std::collections::BTreeMap;

use crate::{line_error, VaultId};

pub struct KeyStore<P: BoxProvider + Clone + Send + Sync + 'static> {
    store: BTreeMap<VaultId, Key<P>>,
}

impl<P: BoxProvider + Clone + Send + Sync + 'static> KeyStore<P> {
    /// Creates a new `KeyStore`.
    pub fn new() -> Self {
        Self { store: BTreeMap::new() }
    }

    /// Gets the key from the `KeyStore` and removes it.  Returns an `Option<Key<P>>`
    pub fn get_key(&mut self, id: VaultId) -> Option<Key<P>> {
        self.store.remove(&id)
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
    pub fn rebuild_keystore(&mut self, keys: BTreeMap<VaultId, Key<P>>) {
        self.store = keys;
    }

    pub fn offload_data(&mut self) -> Vec<u8> {
        let mut key_store: BTreeMap<VaultId, Key<P>> = BTreeMap::new();

        self.store.iter().for_each(|(v, k)| {
            key_store.insert(*v, k.clone());
        });

        bincode::serialize(&key_store).expect(line_error!())
    }

    pub fn get_data(&mut self) -> BTreeMap<VaultId, Key<P>> {
        let mut key_store: BTreeMap<VaultId, Key<P>> = BTreeMap::new();

        self.store.iter().for_each(|(v, k)| {
            key_store.insert(*v, k.clone());
        });

        key_store
    }

    pub fn clear_keys(&mut self) {
        self.store.clear();
    }
}

#[cfg(test)]
mod test {
    // use super::*;
    // use crate::Provider;

    // #[test]
    // fn test_keystore() {
    //     let vid0 = VaultId::random::<Provider>().expect(line_error!());
    //     let vid1 = VaultId::random::<Provider>().expect(line_error!());
    //     let key0 = Key::<Provider>::random().expect(line_error!());

    //     let mut key_store = KeyStore::<Provider>::new();

    //     let key = key_store.create_key(vid0);
    //     let inner_key = key_store.get_key(vid0).expect(line_error!());

    //     assert_eq!(key, inner_key);
    //     assert!(!key_store.store.contains_key(&vid0));

    //     key_store.insert_key(vid0, key);

    //     assert!(key_store.store.contains_key(&vid0));

    //     key_store.insert_key(vid1, key0.clone());

    //     assert!(key_store.store.contains_key(&vid1));

    //     let inserted_key = key_store.insert_key(vid0, key0.clone());

    //     assert_ne!(inserted_key, &key0);

    //     let mut key_vec: Vec<Key<Provider>> = Vec::new();
    //     for _ in 0..10 {
    //         key_vec.push(Key::<Provider>::random().expect(line_error!()));
    //     }

    //     let vault_vec = key_store.rebuild_keystore(key_vec);

    //     assert_eq!(vault_vec.len(), 10);
    //     assert!(!vault_vec.contains(&vid0));
    //     assert!(!vault_vec.contains(&vid1));

    //     for v in vault_vec.iter() {
    //         assert!(key_store.store.contains_key(v));
    //     }
    // }
}
