use std::{
    cell::RefCell,
    thread::{self, JoinHandle},
};

use shared::{line_error, send_until_success, TransactionRequest};

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
    pub fn new_tx(key: &Key<P>, id: Id) {
        let req = DBWriter::<P>::create_chain(key, id);

        send_until_success(TransactionRequest::Write(req.clone()));
    }

    pub fn start(key: Key<P>, id: Id) -> Self {
        Self {
            id,
            vault: Vault::new(key),
        }
    }

    pub fn create_entry(&self, payload: &[u8]) {
        self.vault.take(|store| {
            let (id, req) = store
                .writer(self.id)
                .write(&payload, IndexHint::new(b"").expect(line_error!()))
                .expect(line_error!());
        })
    }
}

impl<P: BoxProvider> Vault<P> {
    pub fn new(key: Key<P>) -> Self {
        let req = send_until_success(TransactionRequest::List).list();
        let store = vault::DBView::load(key.clone(), req).expect(line_error!());
        Self {
            key,
            store: RefCell::new(Some(store)),
        }
    }

    pub fn get_entry_by_index(&self, index: usize) -> Option<Id> {
        let _store = self.store.borrow();
        let store = _store.as_ref().expect(line_error!());
        let mut entries = match store.entries() {
            entries if entries.len() > 0 => entries,
            _ => return None,
        };

        Some(entries.nth(index).expect(line_error!()).0)
    }

    pub fn take<T>(&self, f: impl FnOnce(vault::DBView<P>) -> T) -> T {
        let mut mut_store = self.store.borrow_mut();
        let store = mut_store.take().expect(line_error!());
        let retval = f(store);

        let req = send_until_success(TransactionRequest::List).list();

        *mut_store = Some(vault::DBView::load(self.key.clone(), req).expect(line_error!()));

        retval
    }
}
