use dashmap::DashMap;
use engine::vault::{BoxProvider, DBView, Key, PreparedRead, ReadResult, RecordHint, RecordId};

use std::{collections::HashMap, iter::empty};

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
    fn add_vault(&mut self, key: &Key<P>, uid: RecordId);
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
        unimplemented!()
    }

    pub fn reset_view(&mut self, key: Key<P>) {
        let (req, ids) = self.cache.send(CRequest::List).list();

        ids.into_iter().for_each(|i| println!("{:?}", i));

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

            v.writer(uid).truncate().expect(line_error!());
        };
    }

    fn add_vault(&mut self, key: &Key<P>, uid: RecordId) {
        let view = DBView::load(key.clone(), empty::<ReadResult>()).expect(line_error!());

        let req = view.writer(uid).truncate().expect(line_error!());

        self.cache.send(CRequest::Write(req));

        self.reset_view(key.clone());
    }

    fn read_record(&mut self, uid: RecordId, key: Key<P>) {
        let view = self.get_view(&key);

        if let Some(v) = view {
            let read = v.reader().prepare_read(&uid).expect("unable to read id");

            match read {
                PreparedRead::CacheHit(data) => println!("Plain: {:?}", String::from_utf8(data).unwrap()),
                PreparedRead::CacheMiss(r) => {
                    if let CResult::Read(read) = self.cache.send(CRequest::Read(r)) {
                        let record = v.reader().read(read).expect(line_error!());
                        println!("Plain: {:?}", String::from_utf8(record).unwrap());
                    }
                }
                _ => println!("unable to read record"),
            }
        }

        self.reset_view(key);
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
