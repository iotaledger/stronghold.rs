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

use engine::vault::{BoxProvider, DBView, RecordId, Key, RecordHint, PreparedRead, Kind};

use crate::{
    connection::{send_until_success, CRequest, CResult},
    line_error,
    state::State,
};

use std::{cell::RefCell, collections::HashMap};

use serde::{Deserialize, Serialize};

// structure for the vault.
pub struct Vault<P: BoxProvider> {
    pub key: Key<P>,
    db: RefCell<Option<DBView<P>>>,
}

impl<P: BoxProvider> Vault<P> {
    // create a new vault for the key.
    pub fn new(key: Key<P>) -> Self {
        let reads = send_until_success(CRequest::List).list();
        let db = engine::vault::DBView::load(key.clone(), reads.iter()).expect(line_error!());
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

        let reads = send_until_success(CRequest::List).list();
        *_db = Some(DBView::load(self.key.clone(), reads.iter()).expect(line_error!()));
        retval
    }
}

// structure of the client
pub struct Client<P: BoxProvider> {
    pub db: Vault<P>,
}

impl<P: BoxProvider + Send + Sync + 'static> Client<P> {
    // create a new client
    pub fn new(key: Key<P>) -> Self {
        Self {
            db: Vault::<P>::new(key),
        }
    }

    pub fn write(&self, id: RecordId, payload: Vec<u8>) {
        self.db.take(|db| {
            let mut reqs = vec![];
            let w = db.writer(id);

            if ! db.reader().exists(id) {
                reqs.push(w.truncate().expect(line_error!()));
            }

            reqs.append(&mut w
                .write(&payload, RecordHint::new(b"").expect(line_error!()))
                .expect(line_error!()));

            reqs.into_iter().for_each(|req| {
                send_until_success(CRequest::Write(req));
            });
        })
    }

    // list the ids and hints of all of valid records in the Vault.
    pub fn list_ids(&self) {
        self.db.take(|db| {
            db.records().for_each(|(id, hint)| println!("Id: {:?}, Hint: {:?}", id, hint));
        });
    }

    // list the ids of all of the records in the Vault.
    pub fn list_all_ids(&self) {
        self.db.take(|db| {
            db.all().for_each(|id| println!("Id: {:?}", id));
        });
    }

    // read a record by its ID into plaintext.
    pub fn read_record_by_id(&self, id: RecordId) {
        self.db.take(|db| {
            let plain = match db.reader().prepare_read(&id).expect("unable to read id") {
                PreparedRead::CacheHit(bs) => bs,
                PreparedRead::CacheMiss(req) => {
                    if let CResult::Read(res) = send_until_success(CRequest::Read(req)) {
                        db.reader().read(res).expect(line_error!())
                    } else {
                        panic!("unable to read")
                    }
                }
                PreparedRead::NoSuchRecord => panic!("no such record"),
                PreparedRead::RecordIsEmpty => vec![],
            };

            println!("Plain: {:?}", String::from_utf8(plain).unwrap());
        });
    }

    // Garbage collect the chain and build a new one.
    pub fn perform_gc(&self) {
        self.db.take(|db| {
            db.gc().into_iter().for_each(|req| {
                send_until_success(CRequest::Delete(req));
            });
        });
    }

    // create a revoke transaction in the chain.
    pub fn revoke_record(&self, id: RecordId) {
        self.db.take(|db| {
            let to_write = db.writer(id).revoke().expect(line_error!());
            send_until_success(CRequest::Write(to_write));
        });
    }
}

// structure for the snapshot
#[derive(Serialize, Deserialize)]
pub struct Snapshot<P: BoxProvider> {
    pub key: Key<P>,
    state: HashMap<(Kind, Vec<u8>), Vec<u8>>,
}

impl<P: BoxProvider> Snapshot<P> {
    // create a new snapshot.
    pub fn new(key: Key<P>) -> Self {
        let map = State::offload_data();
        Self { key, state: map }
    }

    // offload the snapshot data to the state map.
    pub fn offload(self) -> Key<P> {
        State::upload_data(self.state);
        self.key
    }
}
