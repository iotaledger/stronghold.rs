// Copyright 2020 IOTA Stiftung
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use crate::{
    connection::{self, TransactionRequest},
    crypt::CRng,
    env::Env,
};

use std::{
    cell::RefCell,
    thread::{self, JoinHandle},
};
use vault::{BoxProvider, DBWriter, Id, Key, RecordHint};

// fuzzing client
pub struct Client<P: BoxProvider> {
    counter: usize,
    id: Id,
    db: Db<P>,
}

// vault wrapper
pub struct Db<P: BoxProvider> {
    key: Key<P>,
    db: RefCell<Option<vault::DBView<P>>>,
}

impl<P: BoxProvider + Send + Sync + 'static> Client<P> {
    // generate new chain in vault
    pub fn create_chain(key: &Key<P>, id: Id) {
        let req = DBWriter::<P>::create_chain(key, id);
        connection::send_until_success(TransactionRequest::Write(req.clone()));
    }

    // start a client
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

    // client worker
    fn worker(self) {
        for _ in 0..self.counter {
            // execute a random transaction
            match CRng::usize(7) {
                0..=2 => self.create_record(),
                3..=5 => self.revoke_record(),
                6 => self.perform_gc(),
                _ => unreachable!(),
            }
            print_status!(b"*");
        }
        print_status!(b"$");
    }
    fn create_record(&self) {
        let payload = CRng::payload();
        self.db.take(|db| {
            let (id, req) = db
                .writer(self.id)
                .write(&payload, RecordHint::new(b"").expect(line_error!()))
                .expect(line_error!());
            Env::shadow_storage()
                .write()
                .expect(line_error!())
                .insert(id.as_ref().to_vec(), payload);
            req.into_iter().for_each(|req| {
                connection::send_until_success(TransactionRequest::Write(req));
            });
        });
    }
    fn revoke_record(&self) {
        let id = match self.db.random_record() {
            Some(id) => id,
            None => return,
        };
        self.db.take(|db| {
            let (to_write, to_delete) = db.writer(self.id).revoke(id).expect(line_error!());
            Env::shadow_storage()
                .write()
                .expect(line_error!())
                .remove(id.as_ref());
            connection::send_until_success(TransactionRequest::Write(to_write));
            connection::send_until_success(TransactionRequest::Delete(to_delete));
        });
    }
    fn perform_gc(&self) {
        self.db.take(|db| {
            let (to_write, to_delete) = db.writer(self.id).gc().expect(line_error!());
            to_write.into_iter().for_each(|req| {
                connection::send_until_success(TransactionRequest::Write(req.clone()));
            });
            to_delete.into_iter().for_each(|req| {
                connection::send_until_success(TransactionRequest::Delete(req.clone()));
            });
        });
    }
}

impl<P: BoxProvider> Db<P> {
    // creates a new vault wrapper
    pub fn new(key: Key<P>) -> Self {
        let req = connection::send_until_success(TransactionRequest::List).list();
        let db = vault::DBView::load(key.clone(), req).expect(line_error!());
        Self {
            key,
            db: RefCell::new(Some(db)),
        }
    }

    // get a random record
    pub fn random_record(&self) -> Option<Id> {
        //get all records
        let _db = self.db.borrow();
        let db = _db.as_ref().expect(line_error!());
        let mut records = match db.records() {
            records if records.len() > 0 => records,
            _ => return None,
        };

        // select random
        let choice = CRng::usize(records.len());
        Some(records.nth(choice).expect(line_error!()).0)
    }

    // calls the function f with the vault and loads a new instance after f has completed.
    pub fn take<T>(&self, f: impl FnOnce(vault::DBView<P>) -> T) -> T {
        let mut _db = self.db.borrow_mut();
        let db = _db.take().expect(line_error!());
        let retval = f(db);

        // reload vault
        let req = connection::send_until_success(TransactionRequest::List).list();
        *_db = Some(vault::DBView::load(self.key.clone(), req).expect(line_error!()));
        retval
    }
}
