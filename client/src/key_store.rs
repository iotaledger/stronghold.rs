// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use engine::vault::{BoxProvider, Key};

use std::collections::HashMap;

use crate::{ids::VaultId, line_error};

pub struct KeyStore<P: BoxProvider + Clone + Send + Sync + 'static> {
    store: HashMap<VaultId, Key<P>>,
}

impl<P: BoxProvider + Clone + Send + Sync + 'static> KeyStore<P> {
    pub fn new() -> Self {
        Self { store: HashMap::new() }
    }

    pub fn get_key(&mut self, id: VaultId) -> Option<Key<P>> {
        self.store.remove(&id)
    }

    pub fn create_key(&mut self, id: VaultId) -> Key<P> {
        let key = self.store.entry(id).or_insert(Key::<P>::random().expect(line_error!()));

        key.clone()
    }

    pub fn insert_key(&mut self, id: VaultId, key: Key<P>) {
        self.store.entry(id).or_insert(key);
    }

    pub fn rebuild_keystore(&mut self, keys: Vec<Key<P>>) {
        let mut store: HashMap<VaultId, Key<P>> = HashMap::new();

        keys.into_iter().for_each(|key| {
            store.insert(VaultId::random::<P>().expect(line_error!()), key);
        });

        self.store = store;
    }

    pub fn get_vault_ids(&mut self) -> Vec<VaultId> {
        let mut ids = Vec::new();

        self.store.keys().into_iter().for_each(|id| ids.push(*id));

        ids
    }
}
