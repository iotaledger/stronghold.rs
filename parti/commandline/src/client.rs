use vault::{BoxProvider, DBView, DBWriter, Id, Key, ListResult, RecordHint};

use crate::{
    connection::{send_until_success, CRequest, CResult},
    line_error,
    state::State,
};

use std::{cell::RefCell, collections::HashMap};

use serde::{Deserialize, Serialize};

// structure of the client
#[derive(Serialize, Deserialize)]
pub struct Client<P: BoxProvider> {
    pub id: Id,
    pub db: Vault<P>,
}

// structure for the vault.
#[derive(Serialize, Deserialize)]
pub struct Vault<P: BoxProvider> {
    pub key: Key<P>,
    db: RefCell<Option<DBView<P>>>,
}

// structure for the snapshot
#[derive(Serialize, Deserialize)]
pub struct Snapshot<P: BoxProvider> {
    pub id: Id,
    pub key: Key<P>,
    state: HashMap<Vec<u8>, Vec<u8>>,
}

impl<P: BoxProvider + Send + Sync + 'static> Client<P> {
    // create a new client
    pub fn new(key: Key<P>, id: Id) -> Self {
        Self {
            id,
            db: Vault::<P>::new(key),
        }
    }

    // create a chain for the user
    pub fn create_chain(key: Key<P>, id: Id) -> Client<P> {
        let req = DBWriter::<P>::create_chain(&key, id);
        // send to the connection interface.
        send_until_success(CRequest::Write(req));

        Self {
            id,
            db: Vault::<P>::new(key),
        }
    }

    // create a record in the vault.
    pub fn create_record(&self, payload: Vec<u8>) {
        self.db.take(|db| {
            let (_, req) = db
                .writer(self.id)
                .write(&payload, RecordHint::new(b"").expect(line_error!()))
                .expect(line_error!());

            req.into_iter().for_each(|req| {
                send_until_success(CRequest::Write(req));
            });
        });
    }

    // list the ids and hints of all of the records in the Vault.
    pub fn list_ids(&self) {
        self.db.take(|db| {
            db.records()
                .for_each(|(id, hint)| println!("Id: {:?}, Hint: {:?}", id, hint));
        });
    }

    // read a record by its ID into plaintext.
    pub fn read_record_by_id(&self, id: Id) {
        self.db.take(|db| {
            let read = db.reader().prepare_read(id).expect("unable to read id");

            if let CResult::Read(read) = send_until_success(CRequest::Read(read)) {
                let record = db.reader().read(read).expect(line_error!());

                println!("Plain: {:?}", String::from_utf8(record).unwrap());
            }
        });
    }

    // Garbage collect the chain and build a new one.
    pub fn perform_gc(&self) {
        self.db.take(|db| {
            let (to_write, to_delete) = db.writer(self.id).gc().expect(line_error!());
            to_write.into_iter().for_each(|req| {
                send_until_success(CRequest::Write(req));
            });
            to_delete.into_iter().for_each(|req| {
                send_until_success(CRequest::Delete(req));
            });
        });
    }

    // Take ownership of an existing chain.  Requires that the new owner knows the old key to unlock the data.
    pub fn take_ownership(&self, old: Id) {
        // load all of the data from the storage vault.
        let ids = send_until_success(CRequest::List).list();
        // use the key to unlock the data.
        let db = DBView::load(self.db.key.clone(), ListResult::new(ids.into())).expect(line_error!());

        let (to_write, to_delete) = db.writer(self.id).take_ownership(&old).expect(line_error!());
        to_write.into_iter().for_each(|req| {
            send_until_success(CRequest::Write(req));
        });
        to_delete.into_iter().for_each(|req| {
            send_until_success(CRequest::Delete(req));
        });
    }

    // create a revoke transaction in the chain.
    pub fn revoke_record_by_id(&self, id: Id) {
        self.db.take(|db| {
            let (to_write, to_delete) = db.writer(self.id).revoke(id).expect(line_error!());

            send_until_success(CRequest::Write(to_write));
            send_until_success(CRequest::Delete(to_delete));
        });
    }
}

impl<P: BoxProvider> Vault<P> {
    // create a new vault for the key.
    pub fn new(key: Key<P>) -> Self {
        let req = send_until_success(CRequest::List).list();
        let db = vault::DBView::load(key.clone(), req).expect(line_error!());
        Self {
            key,
            db: RefCell::new(Some(db)),
        }
    }

    // supply the DBView to a function and update it after its been used.
    pub fn take<T>(&self, f: impl FnOnce(DBView<P>) -> T) -> T {
        let mut _db = self.db.borrow_mut();
        let db = _db.take().expect(line_error!());
        let retval = f(db);

        let req = send_until_success(CRequest::List).list();
        *_db = Some(DBView::load(self.key.clone(), req).expect(line_error!()));
        retval
    }
}

impl<P: BoxProvider> Snapshot<P> {
    // create a new snapshot.
    pub fn new(id: Id, key: Key<P>) -> Self {
        let map = State::offload_data();

        Self { id, key, state: map }
    }

    // offload the snapshot data to the state map.
    pub fn offload(self) -> (Id, Key<P>) {
        State::upload_data(self.state);

        (self.id, self.key)
    }
}
