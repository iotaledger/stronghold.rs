use crate::{
    crypt::CRng,
    env::Env,
    remote::{self, TransactionRequest},
};

use std::{
    cell::RefCell,
    thread::{self, JoinHandle},
};
use vault::{BoxProvider, DBWriter, Id, IndexHint, Key};

pub struct Client<P: BoxProvider> {
    counter: usize,
    id: Id,
    db: Db<P>,
}

pub struct Db<P: BoxProvider> {
    key: Key<P>,
    db: RefCell<Option<vault::DBView<P>>>,
}

impl<P: BoxProvider + Send + Sync + 'static> Client<P> {
    pub fn create_chain(key: &Key<P>, id: Id) {
        let req = DBWriter::<P>::create_chain(key, id);
        remote::send_until_success(TransactionRequest::Write(req.clone()));
    }

    pub fn start(counter: usize, key: Key<P>, id: Id) -> JoinHandle<()> {
        let this = Self {
            counter,
            id,
            db: Db::new(key),
        };
        thread::Builder::new()
            .name(format!("Client thread (ID: {:?})", id))
            .spawn(move || this.worker())
            .expect(line_error!())
    }

    fn worker(self) {
        for _ in 0..self.counter {
            match CRng::usize(7) {
                0..=2 => self.create_entry(),
                3..=5 => self.revoke_entry(),
                6 => self.perform_gc(),
                _ => unreachable!(),
            }
            print_status!(b".");
        }
        print_status!(b"+");
    }
    fn create_entry(&self) {
        let payload = CRng::payload();
        self.db.take(|db| {
            let (id, req) = db
                .writer(self.id)
                .write(&payload, IndexHint::new(b"").expect(line_error!()))
                .expect(line_error!());
            Env::shadow_storage()
                .write()
                .expect(line_error!())
                .insert(id.as_ref().to_vec(), payload);
            req.into_iter().for_each(|req| {
                remote::send_until_success(TransactionRequest::Write(req));
            });
        });
    }
    fn revoke_entry(&self) {
        let id = match self.db.random_entry() {
            Some(id) => id,
            None => return,
        };
        self.db.take(|db| {
            let (to_write, to_delete) = db.writer(self.id).revoke(id).expect(line_error!());
            Env::shadow_storage()
                .write()
                .expect(line_error!())
                .remove(id.as_ref());
            remote::send_until_success(TransactionRequest::Write(to_write));
            remote::send_until_success(TransactionRequest::Delete(to_delete));
        });
    }
    fn perform_gc(&self) {
        self.db.take(|db| {
            let (to_write, to_delete) = db.writer(self.id).gc().expect(line_error!());
            to_write.into_iter().for_each(|req| {
                remote::send_until_success(TransactionRequest::Write(req.clone()));
            });
            to_delete.into_iter().for_each(|req| {
                remote::send_until_success(TransactionRequest::Delete(req.clone()));
            });
        });
    }
}

impl<P: BoxProvider> Db<P> {
    pub fn new(key: Key<P>) -> Self {
        let req = remote::send_until_success(TransactionRequest::List).list();
        let db = vault::DBView::load(key.clone(), req).expect(line_error!());
        Self {
            key,
            db: RefCell::new(Some(db)),
        }
    }

    pub fn random_entry(&self) -> Option<Id> {
        let _db = self.db.borrow();
        let db = _db.as_ref().expect(line_error!());
        let mut entries = match db.entries() {
            entries if entries.len() > 0 => entries,
            _ => return None,
        };

        let choice = CRng::usize(entries.len());
        Some(entries.nth(choice).expect(line_error!()).0)
    }
    pub fn take<T>(&self, f: impl FnOnce(vault::DBView<P>) -> T) -> T {
        let mut _db = self.db.borrow_mut();
        let db = _db.take().expect(line_error!());
        let retval = f(db);

        let req = remote::send_until_success(TransactionRequest::List).list();
        *_db = Some(vault::DBView::load(self.key.clone(), req).expect(line_error!()));
        retval
    }
}
