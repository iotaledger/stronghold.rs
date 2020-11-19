use engine::vault::{
    Base64Encodable, BoxProvider, ChainId, DBView, Key, PreparedRead, ReadResult, RecordHint, RecordId, WriteRequest,
};

use std::{
    collections::{HashMap, HashSet},
    iter::empty,
    marker::PhantomData,
};

use serde::{Deserialize, Serialize};

use crate::{
    bucket::{Blob, Bucket},
    ids::VaultId,
    line_error,
    provider::Provider,
    ClientId,
};

pub struct Client<P: BoxProvider + Clone + Send + Sync + 'static> {
    id: ClientId,
    key_ref: HashMap<VaultId, Key<P>>,
    _provider: PhantomData<P>,
}

pub struct Snapshot<P: BoxProvider + Clone + Send + Sync> {
    pub id: ClientId,
    pub keys: HashSet<Key<P>>,
    pub state: HashMap<Vec<u8>, Vec<ReadResult>>,
}

impl<P: BoxProvider + Clone + Send + Sync + 'static> Client<P> {
    pub fn new(id: ClientId) -> Self {
        Self {
            id,
            key_ref: vec![],
            _provider: PhantomData,
        }
    }

    pub fn new_from_snapshot(snapshot: Snapshot<P>) -> Self {
        unimplemented!()
    }

    pub fn add_vault(&mut self, key: &Key<P>) {}

    pub fn create_record(&mut self, key: Key<P>, payload: Vec<u8>) {}

    pub fn read_record(&mut self, key: Key<P>, id: RecordId) {}

    pub fn preform_gc(&mut self, key: Key<P>) {}

    pub fn revoke_record_by_id(&mut self, id: RecordId, key: Key<P>) {}

    pub fn list_valid_ids_for_vault(&mut self, key: Key<P>) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stuff() {
        let id1 = RecordId::random::<Provider>().expect(line_error!());
        let id2 = RecordId::random::<Provider>().expect(line_error!());
        let key1 = Key::<Provider>::random().expect(line_error!());
        let key2 = Key::<Provider>::random().expect(line_error!());
        let mut map: HashMap<Key<Provider>, Option<DBView<Provider>>> = HashMap::new();
        let mut writes1 = vec![];
        let mut writes2 = vec![];
        let view1 = DBView::load(key1.clone(), empty::<ReadResult>()).expect(line_error!());
        let view2 = DBView::load(key2.clone(), empty::<ReadResult>()).expect(line_error!());
        let mut writer1 = view1.writer(id1);
        let mut writer2 = view2.writer(id2);
        writes1.push(writer1.truncate().expect(line_error!()));
        writes2.push(writer2.truncate().expect(line_error!()));
        writes1.append(
            &mut writer1
                .write(b"some data", RecordHint::new(b"").expect(line_error!()))
                .expect(line_error!()),
        );
        writes2.append(
            &mut writer2
                .write(b"some data", RecordHint::new(b"").expect(line_error!()))
                .expect(line_error!()),
        );
        let view1 = DBView::load(key1.clone(), writes1.iter().map(write_to_read)).expect(line_error!());
        let view2 = DBView::load(key2.clone(), writes2.iter().map(write_to_read)).expect(line_error!());
        map.insert(key1.clone(), Some(view1));
        map.insert(key2.clone(), Some(view2));
        let view1 = map.remove(&key1).unwrap().unwrap();
        let id12 = RecordId::random::<Provider>().expect(line_error!());
        let id22 = RecordId::random::<Provider>().expect(line_error!());
        let mut writer1 = view1.writer(id12);
        writes1.push(writer1.truncate().expect(line_error!()));
        writes1.append(
            &mut writer1
                .write(b"some data", RecordHint::new(b"").expect(line_error!()))
                .expect(line_error!()),
        );
        writes1.push(writer1.truncate().expect(line_error!()));
        let view1 = DBView::load(key1.clone(), writes1.iter().map(write_to_read)).expect(line_error!());
        map.insert(key1.clone(), Some(view1));

        let view1 = DBView::load(key1.clone(), writes1.iter().map(write_to_read)).expect(line_error!());

        let reader = view1.reader();

        let res = reader.prepare_read(&id1).expect(line_error!());

        match res {
            PreparedRead::CacheHit(v) => println!("{:?}", std::str::from_utf8(&v)),
            _ => println!("no data"),
        }
    }
    fn write_to_read(write: &WriteRequest) -> ReadResult {
        ReadResult::new(write.kind(), write.id(), write.data())
    }
}
