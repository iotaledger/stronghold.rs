use zeroize_derive::Zeroize;

use engine::vault::{BoxProvider, Key};

use std::collections::HashMap;

use crate::{ids::VaultId, line_error};

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
    store: HashMap<VaultId, Key<P>>,
}

impl<P: BoxProvider + Clone + Send + Sync + 'static> KeyStore<P> {
    pub fn new() -> Self {
        Self { store: HashMap::new() }
    }

    pub fn send_key_and_id(&self, id: VaultId) {
        unimplemented!()
    }

    pub fn create_key_for_vault(&mut self, id: VaultId) {
        self.store.entry(id).or_insert(Key::<P>::random().expect(line_error!()));
    }
}
