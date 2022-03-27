// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::Provider;
use engine::vault::{BoxProvider, Key, NCKey, VaultId};

// use crate::vault::{
//     crypto_box::{BoxProvider, Key, NCKey},
//     VaultId,
// };
use std::collections::HashMap;

/// The [`KeyStore`] keeps a map of [`VaultId`] -> [Vec<u8>] representing
/// encrypted [`Key<P>`] using the `master_key`.
/// `master_key` is stored in a non-contiguous data structure [`NCKey<P>`]
/// for more security
pub struct KeyStore<P>
where
    P: BoxProvider,
{
    store: HashMap<VaultId, Vec<u8>>,
    master_key: NCKey<P>,
}

impl<P> Default for KeyStore<P>
where
    P: BoxProvider,
{
    fn default() -> Self {
        Self {
            store: HashMap::new(),
            master_key: NCKey::<P>::random(),
        }
    }
}

impl<P> KeyStore<P>
where
    P: BoxProvider,
{
    /// Gets the encrypted key from the [`KeyStore`] and removes it.
    /// Decrypt it with the `master_key` and `vault_id` as salt.
    pub fn take_key(&mut self, id: VaultId) -> Option<Key<P>> {
        let enc_key = self.store.remove(&id)?;
        self.master_key.decrypt_key(enc_key, id).ok()
    }
    /// Gets the encrypted key from the [`KeyStore`].
    /// Decrypt it with the `master_key` and `vault_id` as salt.
    pub fn get_key(&self, id: VaultId) -> Option<Key<P>> {
        let enc_key = self.store.get(&id)?.clone();
        self.master_key.decrypt_key(enc_key, id).ok()
    }

    /// Checks to see if the vault exists.
    pub fn vault_exists(&self, id: VaultId) -> bool {
        self.store.contains_key(&id)
    }

    /// Creates a new key in the [`KeyStore`] if it does not exist yet
    /// Returns None if it fails
    /// Returns None if it fails
    pub fn create_key(&mut self, id: VaultId) -> Result<Key<P>, P::Error> {
        let vault_key = Key::random();
        self.get_or_insert_key(id, vault_key)
    }

    /// Inserts a key into the [`KeyStore`] by [`VaultId`].
    /// If the [`VaultId`] already exists, it just returns the existing [`Key<P>`]
    pub fn get_or_insert_key(&mut self, id: VaultId, key: Key<P>) -> Result<Key<P>, P::Error> {
        let vault_key = if let Some(key) = self.get_key(id) { key } else { key };
        let enc_key = self.master_key.encrypt_key(&vault_key, id)?;
        self.store.insert(id, enc_key);
        Ok(vault_key)
    }

    /// Inserts a key into the [`KeyStore`] by [`VaultId`] and overrides the old key.
    pub fn insert_key(&mut self, id: VaultId, key: Key<P>) -> Result<(), P::Error> {
        let vault_key = key;
        let enc_key = self.master_key.encrypt_key(&vault_key, id)?;
        self.store.insert(id, enc_key);
        Ok(())
    }

    /// Rebuilds the [`KeyStore`] while throwing out any existing [`VaultId`], [`Key<P>`] pairs.  Accepts a
    /// [`Vec<Key<P>>`] and returns then a [`Vec<VaultId>`]; primarily used to repopulate the state from a
    /// snapshot.
    pub fn rebuild_keystore(&mut self, keys: HashMap<VaultId, Key<P>>) -> Result<(), P::Error> {
        let mut new_ks = KeyStore::default();
        for (id, key) in keys.into_iter() {
            new_ks.get_or_insert_key(id, key)?;
        }
        *self = new_ks;
        Ok(())
    }

    /// Gets the state data in a hashmap format for the snapshot.
    pub fn get_data(&mut self) -> HashMap<VaultId, Key<P>> {
        let mut key_store: HashMap<VaultId, Key<P>> = HashMap::new();

        self.store.iter().for_each(|(id, enc_key)| {
            key_store.insert(
                *id,
                self.master_key
                    .decrypt_key(enc_key.clone(), *id)
                    .expect("Failed to decrypt from the keystore"),
            );
        });

        key_store
    }

    /// Clear the key store.
    pub fn clear_keys(&mut self) {
        self.store.clear();
    }
}
