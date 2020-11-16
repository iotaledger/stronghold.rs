use dashmap::DashMap;
use engine::vault::{BoxProvider, ChainId, DBView, DBWriter, Key, RecordHint, RecordId};

use std::collections::HashMap;

use crate::{
    cache::{CRequest, CResult, Cache},
    client::Snapshot,
    line_error,
};

pub struct Blob<P: BoxProvider + Send + Sync + Clone + 'static> {
    vaults: DashMap<Key<P>, Option<DBView<P>>>,
    cache: Cache,
}

pub trait Bucket<P: BoxProvider + Send + Sync + Clone + 'static> {
    fn create_record(&mut self, uid: RecordId, key: Key<P>, payload: Vec<u8>);
    fn add_vault(&mut self, key: &Key<P>, uid: ChainId);
    fn read_record(&mut self, uid: RecordId, key: Key<P>);
    fn garbage_collect(&mut self, uid: RecordId, key: Key<P>);
    fn revoke_record(&mut self, uid: RecordId, tx_id: RecordId, key: Key<P>);
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

        self.vaults.insert(
            key.clone(),
            Some(DBView::load(key, req.into_iter()).expect(line_error!())),
        );
    }
}

impl<P: BoxProvider + Clone + Send + Sync + 'static> Bucket<P> for Blob<P> {
    fn create_record(&mut self, uid: RecordId, key: Key<P>, payload: Vec<u8>) {
        let view = self.get_view(&key);

        if let Some(v) = view {
            let req = v
                .writer(uid)
                .write(&payload, RecordHint::new(b"").expect(line_error!()))
                .expect(line_error!());

            req.into_iter().for_each(|r| {
                self.cache.send(CRequest::Write(r));
            });
        };
    }

    fn add_vault(&mut self, key: &Key<P>, uid: ChainId) {
        unimplemented!()
    }

    fn read_record(&mut self, uid: RecordId, key: Key<P>) {
        unimplemented!()
    }

    fn garbage_collect(&mut self, uid: RecordId, key: Key<P>) {
        unimplemented!()
    }

    fn revoke_record(&mut self, uid: RecordId, tx_id: RecordId, key: Key<P>) {
        unimplemented!()
    }

    fn list_all_valid_by_key(&mut self, key: Key<P>) {
        unimplemented!()
    }

    fn offload_data(self) -> (Vec<Key<P>>, HashMap<Vec<u8>, Vec<u8>>) {
        unimplemented!()
    }
}
