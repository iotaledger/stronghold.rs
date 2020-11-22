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
}
