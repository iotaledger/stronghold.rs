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
        let key = self
            .store
            .entry(id)
            .or_insert_with(|| Key::<P>::random().expect(line_error!()));

        key.clone()
    }

    pub fn insert_key(&mut self, id: VaultId, key: Key<P>) {
        self.store.entry(id).or_insert(key);
    }

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
