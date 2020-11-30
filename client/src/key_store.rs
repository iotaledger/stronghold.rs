// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use engine::vault::{BoxProvider, Key};

use std::collections::HashMap;

use crate::{ids::VaultId, line_error};

pub struct KeyStore<P: BoxProvider + Clone + Send + Sync + 'static> {
    store: HashMap<VaultId, Key<P>>,
}

impl<P: BoxProvider + Clone + Send + Sync + 'static> KeyStore<P> {
    /// Creates a new `KeyStore`.
    pub fn new() -> Self {
        Self { store: HashMap::new() }
    }

    /// gets the key from the `KeyStore` by removing it.  Returns an `Option<Key<P>>`
    pub fn get_key(&mut self, id: VaultId) -> Option<Key<P>> {
        self.store.remove(&id)
    }

    /// Creates a new key for the `VaultId` and returns it.
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
    pub fn rebuild_keystore(&mut self, keys: Vec<Key<P>>) -> Vec<VaultId> {
        let mut store: HashMap<VaultId, Key<P>> = HashMap::new();
        let mut id_buffer: Vec<VaultId> = Vec::new();

        keys.into_iter().for_each(|key| {
            let vid = VaultId::random::<P>().expect(line_error!());
            store.insert(vid, key);

            id_buffer.push(vid);
        });

        self.store = store;

        id_buffer
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::provider::Provider;

    #[test]
    fn test_keystore() {
        let vid0 = VaultId::random::<Provider>().expect(line_error!());
        let vid1 = VaultId::random::<Provider>().expect(line_error!());
        let key0 = Key::<Provider>::random().expect(line_error!());

        let mut key_store = KeyStore::<Provider>::new();

        let key = key_store.create_key(vid0);
        let inner_key = key_store.get_key(vid0).expect(line_error!());

        assert_eq!(key, inner_key);
        assert!(!key_store.store.contains_key(&vid0));

        key_store.insert_key(vid0, key);

        assert!(key_store.store.contains_key(&vid0));

        key_store.insert_key(vid1, key0.clone());

        assert!(key_store.store.contains_key(&vid1));

        let inserted_key = key_store.insert_key(vid0, key0.clone());

        assert_ne!(inserted_key, &key0);

        let mut key_vec: Vec<Key<Provider>> = Vec::new();
        for _ in 0..10 {
            key_vec.push(Key::<Provider>::random().expect(line_error!()));
        }

        let vault_vec = key_store.rebuild_keystore(key_vec);

        assert_eq!(vault_vec.len(), 10);
        assert!(!vault_vec.contains(&vid0));
        assert!(!vault_vec.contains(&vid1));

        for v in vault_vec.iter() {
            assert!(key_store.store.contains_key(v));
        }
    }
}
