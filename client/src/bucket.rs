use dashmap::DashMap;
use engine::vault::{BoxProvider, DBView, Key, PreparedRead, ReadResult, RecordHint, RecordId};

use std::{collections::HashMap, iter::empty};

use crate::{
    cache::{write_to_read, CRequest, CResult, Cache},
    client::Snapshot,
    ids::VaultId,
    line_error, ClientId,
};

pub struct Blob<P: BoxProvider + Send + Sync + Clone + 'static> {
    vaults: DashMap<Key<P>, Option<DBView<P>>>,
    cache: Cache,
}

pub trait Bucket<P: BoxProvider + Send + Sync + Clone + 'static> {
    fn create_record(&mut self, vid: VaultId, key: Key<P>, payload: Vec<u8>);
    fn add_vault(&mut self) -> VaultId;
    fn read_record(&mut self, vid: VaultId, id: RecordId, key: Key<P>);
    fn garbage_collect(&mut self, vid: VaultId, key: Key<P>);
    fn revoke_record(&mut self, vid: VaultId, tx_id: RecordId, key: Key<P>);
    fn list_all_valid_by_key(&mut self, vid: VaultId, key: Key<P>);
    fn offload_data(self) -> (Vec<Key<P>>, HashMap<Vec<u8>, Vec<u8>>);
}

impl<P: BoxProvider + Clone + Send + Sync + 'static> Blob<P> {
    pub fn new() -> Self {
        let cache = Cache::new();
        let vaults = DashMap::new();

        Self { cache, vaults }
    }

    pub fn new_from_snapshot(snapshot: Snapshot<P>) -> Self {
        unimplemented!()
        //     let cache = Cache::new();
        //     let vaults = DashMap::new();

        //     cache.upload_data(snapshot.state);

        //     let keys = snapshot.keys;

        //     keys.iter().for_each(|k| {
        //         vaults.insert(k.clone(), None);
        //     });

        //     Self { cache, vaults }
    }

    pub fn create_view(&mut self, key: Key<P>) -> DBView<P> {
        let reads = empty::<ReadResult>();

        DBView::load(key, reads).expect(line_error!())
    }

    pub fn get_view(&mut self, key: &Key<P>) -> Option<DBView<P>> {
        let (_, view) = self.vaults.remove(&key).expect(line_error!());

        view
    }

    pub fn reset_view(&mut self, key: Key<P>, id: VaultId) {
        let lists = self.cache.send(CRequest::List(id)).list();

        self.vaults
            .insert(key.clone(), Some(DBView::load(key, lists.iter()).expect(line_error!())));
    }
}

impl<P: BoxProvider + Clone + Send + Sync + 'static> Bucket<P> for Blob<P> {
    fn create_record(&mut self, vid: VaultId, key: Key<P>, payload: Vec<u8>) {
        if let Some(view) = self.get_view(&key) {
            let id = RecordId::random::<P>().expect(line_error!());

            let mut writer = view.writer(id);

            writer
                .write(&payload, RecordHint::new(b"").expect(line_error!()))
                .expect(line_error!())
                .into_iter()
                .for_each(|write| {
                    self.cache.send(CRequest::Write((vid, write)));
                });

            self.cache
                .send(CRequest::Write((vid, writer.truncate().expect(line_error!()))));

            self.reset_view(key, vid);
        }
    }

    fn add_vault(&mut self) -> VaultId {
        let key = Key::<P>::random().expect(line_error!());
        let vid = VaultId::random::<P>().expect(line_error!());
        let id = RecordId::random::<P>().expect(line_error!());

        let view = self.create_view(key.clone());

        let mut writer = view.writer(id);

        self.cache
            .send(CRequest::Write((vid, writer.truncate().expect(line_error!()))));

        self.reset_view(key, vid);

        vid
    }

    fn read_record(&mut self, vid: VaultId, id: RecordId, key: Key<P>) {
        unimplemented!()
    }

    fn garbage_collect(&mut self, vid: VaultId, key: Key<P>) {
        unimplemented!()
    }

    fn revoke_record(&mut self, vid: VaultId, tx_id: RecordId, key: Key<P>) {
        if let Some(view) = self.get_view(&key) {
            let mut writer = view.writer(tx_id);

            writer.revoke().expect(line_error!());
        }

        self.reset_view(key.clone(), vid);
    }

    fn list_all_valid_by_key(&mut self, vid: VaultId, key: Key<P>) {
        if let Some(view) = self.get_view(&key) {
            view.records().for_each(|(id, hint)| println!("{:?}, {:?}", id, hint));
        }

        self.reset_view(key, vid);
    }

    fn offload_data(self) -> (Vec<Key<P>>, HashMap<Vec<u8>, Vec<u8>>) {
        unimplemented!()
    }
}
