use std::{
    cell::RefCell,
    thread::{self, JoinHandle},
};

use vault::{BoxProvider, DBWriter, Id, IndexHint, Key};

pub struct Client<P: BoxProvider> {
    id: Id,
    vault: Vault<P>,
}

pub struct Vault<P: BoxProvider> {
    key: Key<P>,
    store: RefCell<Option<vault::DBView<P>>>,
}

impl<P: BoxProvider + Send + Sync + 'static> Client<P> {
    pub fn new_store(key: &Key<P>, id: Id) {
        let req = DBWriter::<P>::create_chain(key, id);
    }
}
