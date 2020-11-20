use zeroize_derive::Zeroize;

use engine::vault::{BoxProvider, DBView, Key, ReadResult};

use crate::{ids::VaultId, line_error};

use dashmap::DashMap;

#[derive(Clone, Debug, Zeroize)]
pub struct Value<T>(T);

impl<T> Value<T> {
    pub fn new(val: T) -> Self {
        Self(val)
    }

    pub fn inner(self) -> T {
        self.0
    }
}

pub struct KeyStore<P: BoxProvider + Clone + Send + Sync + 'static> {
    store: DashMap<VaultId, Key<P>>,
}

impl<P: BoxProvider + Clone + Send + Sync + 'static> KeyStore<P> {
    pub fn new() -> Self {
        Self { store: DashMap::new() }
    }

    pub fn get_key_and_id(&self, id: VaultId) -> (VaultId, Key<P>) {
        self.store.remove(&id).expect(line_error!())
    }

    pub fn create_key_for_vault(&mut self, id: VaultId) -> VaultId {
        self.store.entry(id).or_insert(Key::<P>::random().expect(line_error!()));

        id
    }

    pub fn insert_key(&self, id: VaultId, key: Key<P>) {
        self.store.entry(id).or_insert(key);
    }
}
