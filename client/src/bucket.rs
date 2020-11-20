use dashmap::DashMap;
use engine::vault::{BoxProvider, DBView, Key, PreparedRead, ReadResult, RecordHint, RecordId};

use std::{collections::HashMap, iter::empty};

use crate::{
    cache::{CRequest, Cache},
    client::Snapshot,
    ids::VaultId,
    line_error,
};

pub struct Blob<P: BoxProvider + Send + Sync + Clone + 'static> {
    vaults: DashMap<VaultId, Option<DBView<P>>>,
    cache: Cache,
}

pub trait Bucket<P: BoxProvider + Send + Sync + Clone + 'static> {
    fn create_record(&mut self, vid: VaultId, key: Key<P>, payload: Vec<u8>);
    fn add_vault(&mut self) -> (VaultId, Key<P>);
    fn read_record(&mut self, vid: VaultId, id: RecordId, key: Key<P>);
    fn garbage_collect(&mut self, vid: VaultId, key: Key<P>);
    fn revoke_record(&mut self, vid: VaultId, tx_id: RecordId);
    fn list_all_valid_by_key(&mut self, vid: VaultId);
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

    pub fn get_view(&mut self, vid: VaultId) -> Option<DBView<P>> {
        let (_, view) = self.vaults.remove(&vid).expect(line_error!());

        view
    }

    pub fn reset_view(&mut self, key: Key<P>, vid: VaultId) {
        let lists = self.cache.send(CRequest::List(vid)).list();

        self.vaults
            .insert(vid, Some(DBView::load(key, lists.iter()).expect(line_error!())));
    }
}

impl<P: BoxProvider + Clone + Send + Sync + 'static> Bucket<P> for Blob<P> {
    fn create_record(&mut self, vid: VaultId, key: Key<P>, payload: Vec<u8>) {
        if let Some(view) = self.get_view(vid) {
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

    fn add_vault(&mut self) -> (VaultId, Key<P>) {
        let key = Key::<P>::random().expect(line_error!());
        let vid = VaultId::random::<P>().expect(line_error!());
        let id = RecordId::random::<P>().expect(line_error!());

        let view = self.create_view(key.clone());

        let mut writer = view.writer(id);

        self.cache
            .send(CRequest::Write((vid, writer.truncate().expect(line_error!()))));

        self.reset_view(key.clone(), vid);

        (vid, key)
    }

    fn read_record(&mut self, vid: VaultId, id: RecordId, key: Key<P>) {
        unimplemented!()
    }

    fn garbage_collect(&mut self, vid: VaultId, key: Key<P>) {
        unimplemented!()
    }

    fn revoke_record(&mut self, vid: VaultId, tx_id: RecordId) {
        if let Some(view) = self.get_view(vid) {
            let mut writer = view.writer(tx_id);

            self.cache
                .send(CRequest::Delete((vid, writer.revoke().expect(line_error!()))));
        }
    }

    fn list_all_valid_by_key(&mut self, vid: VaultId) {
        if let Some(view) = self.get_view(vid) {
            view.records().for_each(|(id, hint)| println!("{:?}, {:?}", id, hint));
        }
    }

    fn offload_data(self) -> (Vec<Key<P>>, HashMap<Vec<u8>, Vec<u8>>) {
        unimplemented!()
    }
}
