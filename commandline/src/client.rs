use vault::{BoxProvider, DBView, DBWriter, Id, IndexHint, Key};

use crate::{
    connection::{send, CRequest},
    line_error,
};

use std::cell::RefCell;

pub struct Client<P: BoxProvider> {
    owner: Id,
    vault: Vault<P>,
}

pub struct Vault<P: BoxProvider> {
    pub key: Key<P>,
    pub entries: RefCell<Option<DBView<P>>>,
}

impl<P: BoxProvider + Send + Sync + 'static> Client<P> {
    pub fn init_chain(key: &Key<P>, id: Id) {
        let write = DBWriter::<P>::create_chain(key, id);
        send(CRequest::Write(write.clone()));
    }

    pub fn new(key: Key<P>, owner: Id) -> Client<P> {
        Self {
            owner,
            vault: Vault::new(key),
        }
    }

    pub fn new_entry(&self, payload: Vec<u8>) {
        self.vault.call(|store| {
            let (id, res) = store
                .writer(self.owner)
                .write(&payload, IndexHint::new(b"").expect(line_error!()))
                .expect(line_error!());

            res.into_iter().for_each(|ent| {
                send(CRequest::Write(ent));
            });
        });
    }

    pub fn revoke_entry(&self, id: Id) {
        self.vault.call(|store| {
            let (write, delete) = store.writer(self.owner).revoke(id).expect(line_error!());

            send(CRequest::Write(write));
            send(CRequest::Delete(delete));
        });
    }

    pub fn preform_gc(&self) {
        self.vault.call(|store| {
            let (write, delete) = store.writer(self.owner).gc().expect(line_error!());
            write.into_iter().for_each(|wr| {
                send(CRequest::Write(wr.clone()));
            });

            delete.into_iter().for_each(|del| {
                send(CRequest::Delete(del.clone()));
            });
        });
    }
}

impl<P: BoxProvider> Vault<P> {
    pub fn new(key: Key<P>) -> Self {
        let res = send(CRequest::List).unwrap().list();
        let view = DBView::load(key.clone(), res).expect(line_error!());
        Self {
            key,
            entries: RefCell::new(Some(view)),
        }
    }

    pub fn call<T>(&self, f: impl FnOnce(DBView<P>) -> T) -> T {
        let mut reference = self.entries.borrow_mut();

        let view = reference.take().expect(line_error!());
        let val = f(view);

        let res = send(CRequest::List).unwrap().list();
        *reference = Some(DBView::load(self.key.clone(), res).expect(line_error!()));

        val
    }
}
