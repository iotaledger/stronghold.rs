use vault::{BoxProvider, DBWriter, Id, Key, ReadResult, RecordHint};

use crate::{
    connection::{send_until_success, CRequest},
    line_error,
    state::State,
};

use std::{cell::RefCell, collections::HashMap};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Client<P: BoxProvider> {
    pub id: Id,
    pub db: Db<P>,
}

#[derive(Serialize, Deserialize)]
pub struct Db<P: BoxProvider> {
    pub key: Key<P>,
    db: RefCell<Option<vault::DBView<P>>>,
}

#[derive(Serialize, Deserialize)]
pub struct Snapshot<P: BoxProvider> {
    pub id: Id,
    pub key: Key<P>,
    state: HashMap<Vec<u8>, Vec<u8>>,
}

impl<P: BoxProvider + Send + Sync + 'static> Client<P> {
    pub fn new(id: Id, key: Key<P>) -> Self {
        Self {
            id,
            db: Db::<P>::new(key),
        }
    }

    pub fn create_chain(key: Key<P>, id: Id) -> Client<P> {
        let req = DBWriter::<P>::create_chain(&key.clone(), id);
        send_until_success(CRequest::Write(req.clone()));

        let client = Self {
            id: id,
            db: Db::<P>::new(key),
        };

        client
    }

    pub fn create_entry(&self, payload: Vec<u8>) {
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

    pub fn list_ids(&self) {
        self.db.take(|db| {
            db.entries()
                .for_each(|(id, hint)| println!("Id: {:?}, Hint: {:?}", id, hint));
        });
    }

    pub fn read_entry_by_id(&self, id: Id) {
        self.db.take(|db| {
            let read = db.reader().prepare_read(id).expect("unable to read id");
            if let Some(data) = State::backup_map().read().unwrap().get(read.id()).cloned() {
                let entry = db
                    .reader()
                    .read(ReadResult::new(read.into(), data))
                    .expect(line_error!());

                println!("Plain: {:?}", String::from_utf8(entry).unwrap());
            };
        });
    }

    pub fn revoke_entry(&self, id: Id) {
        self.db.take(|db| {
            let (to_write, to_delete) = db.writer(self.id).revoke(id).expect(line_error!());

            send_until_success(CRequest::Write(to_write));
            send_until_success(CRequest::Delete(to_delete));
        });
    }

    pub fn perform_gc(&self) {
        self.db.take(|db| {
            let (to_write, to_delete) = db.writer(self.id).gc().expect(line_error!());
            to_write.into_iter().for_each(|req| {
                send_until_success(CRequest::Write(req.clone()));
            });
            to_delete.into_iter().for_each(|req| {
                send_until_success(CRequest::Delete(req.clone()));
            });
        });
    }
}

impl<P: BoxProvider> Db<P> {
    pub fn new(key: Key<P>) -> Self {
        let req = send_until_success(CRequest::List).list();
        let db = vault::DBView::load(key.clone(), req).expect(line_error!());
        Self {
            key,
            db: RefCell::new(Some(db)),
        }
    }

    pub fn take<T>(&self, f: impl FnOnce(vault::DBView<P>) -> T) -> T {
        let mut _db = self.db.borrow_mut();
        let db = _db.take().expect(line_error!());
        let retval = f(db);

        let req = send_until_success(CRequest::List).list();
        *_db = Some(vault::DBView::load(self.key.clone(), req).expect(line_error!()));
        retval
    }
}

impl<P: BoxProvider> Snapshot<P> {
    pub fn new(id: Id, key: Key<P>) -> Self {
        let mut map: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        State::backup_map()
            .write()
            .expect("failed to read map")
            .clone()
            .into_iter()
            .for_each(|(k, v)| {
                map.insert(k, v);
            });

        Self {
            id,
            key,
            state: map,
        }
    }

    pub fn offload(self) -> (Id, Key<P>) {
        self.state.into_iter().for_each(|(k, v)| {
            State::backup_map()
                .write()
                .expect("couldn't open map")
                .insert(k, v);
        });

        (self.id, self.key)
    }
}
