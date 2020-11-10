use engine::vault::{BoxProvider, DBView, DBWriter, Id, Key, RecordHint};

use crate::{
    line_error,
    storage::{
        cache::{CRequest, CResult, Cache},
        client::Snapshot,
    },
};

use dashmap::DashMap;

use std::collections::HashMap;

#[derive(Clone)]
pub struct Blob<P: BoxProvider + Send + Sync + Clone + 'static> {
    vaults: DashMap<Key<P>, Option<DBView<P>>>,
    cache: Cache,
}

pub trait Bucket<P: BoxProvider + Send + Sync + Clone + 'static> {
    fn create_record(&mut self, uid: Id, key: Key<P>, payload: Vec<u8>, hint: &[u8]) -> Option<Id>;
    fn add_vault(&mut self, key: &Key<P>, uid: Id);
    fn read_record(&mut self, uid: Id, key: Key<P>);
    fn garbage_collect(&mut self, uid: Id, key: Key<P>);
    fn revoke_record(&mut self, uid: Id, tx_id: Id, key: Key<P>);
    fn list_all_valid_by_key(&mut self, key: Key<P>);
    fn offload_data(self) -> (Vec<Key<P>>, HashMap<Vec<u8>, Vec<u8>>);
}

impl<P: BoxProvider + Clone + Send + Sync + 'static> Blob<P> {
    pub fn new() -> Self {
        let cache = Cache::new();
        let vaults = DashMap::new();

        Self { cache, vaults }
    }

    pub fn new_from_snapshot(snapshot: Snapshot<P>) -> Self {
        let cache = Cache::new();
        let vaults = DashMap::new();

        cache.upload_data(snapshot.state);

        let keys = snapshot.keys;

        keys.iter().for_each(|k| {
            vaults.insert(k.clone(), None);
        });

        Self { cache, vaults }
    }

    pub fn get_view(&mut self, key: &Key<P>) -> Option<DBView<P>> {
        let (_, view) = self.vaults.remove(key).expect(line_error!());

        view
    }

    pub fn reset_view(&mut self, key: Key<P>) {
        let req = self.cache.send(CRequest::List).list();
        self.vaults
            .insert(key.clone(), Some(DBView::load(key, req).expect(line_error!())));
    }
}

impl<P: BoxProvider + Clone + Send + Sync + 'static> Bucket<P> for Blob<P> {
    fn create_record(&mut self, uid: Id, key: Key<P>, payload: Vec<u8>, hint: &[u8]) -> Option<Id> {
        let view = self.get_view(&key);

        let id = if let Some(v) = view {
            let (id, req) = v
                .writer(uid)
                .write(&payload, RecordHint::new(hint).expect(line_error!()))
                .expect(line_error!());
            req.into_iter().for_each(|r| {
                self.cache.send(CRequest::Write(r));
            });
            Some(id)
        } else {
            None
        };

        self.reset_view(key);

        id
    }

    fn add_vault(&mut self, key: &Key<P>, uid: Id) {
        let req = DBWriter::<P>::create_chain(&key, uid);

        self.cache.send(CRequest::Write(req));

        self.reset_view(key.clone());
    }

    fn read_record(&mut self, uid: Id, key: Key<P>) {
        let view = self.get_view(&key);
        if let Some(v) = view {
            let read = v.reader().prepare_read(uid).expect("unable to read id");
            if let CResult::Read(read) = self.cache.send(CRequest::Read(read)) {
                let record = v.reader().read(read).expect(line_error!());
                println!("Plain: {:?}", String::from_utf8(record).unwrap());
            }
        }

        self.reset_view(key);
    }

    fn garbage_collect(&mut self, uid: Id, key: Key<P>) {
        let view = self.get_view(&key);

        if let Some(v) = view {
            let (write, delete) = v.writer(uid).gc().expect(line_error!());
            write.into_iter().for_each(|r| {
                self.cache.send(CRequest::Write(r));
            });

            delete.into_iter().for_each(|r| {
                self.cache.send(CRequest::Delete(r));
            });
        }
        self.reset_view(key);
    }

    fn revoke_record(&mut self, uid: Id, tx_id: Id, key: Key<P>) {
        let view = self.get_view(&key);

        if let Some(v) = view {
            let (to_write, to_delete) = v.writer(uid).revoke(tx_id).expect(line_error!());

            self.cache.send(CRequest::Write(to_write));
            self.cache.send(CRequest::Delete(to_delete));
        };

        self.reset_view(key);
    }

    fn list_all_valid_by_key(&mut self, key: Key<P>) {
        let view = self.get_view(&key);

        if let Some(v) = view {
            v.records()
                .for_each(|(id, hint)| println!("Id: {:?}, Hint: {:?}", id, hint))
        }

        self.reset_view(key);
    }

    fn offload_data(self) -> (Vec<Key<P>>, HashMap<Vec<u8>, Vec<u8>>) {
        let dashmap = self.vaults.clone();
        let keys: Vec<Key<P>> = dashmap.into_read_only().keys().into_iter().map(|k| k.clone()).collect();

        (keys, self.cache.offload_data())
    }
}
