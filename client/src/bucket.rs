// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use engine::{
    store::Cache,
    vault::{BoxProvider, DBView, Key, PreparedRead, ReadResult, RecordHint, RecordId, WriteRequest},
};

use std::time::Duration;

use std::collections::HashMap;

use crate::line_error;

/// A `Bucket` cache of the Data for stronghold. Contains a `HashMap<Key<P>, Option<DBView<P>>>` pairing the vault
/// `Key<P>` and the vault `DBView<P>` together. Also contains a `HashMap<Key<P>, Vec<ReadResult>>` which pairs the
/// backing data with the associated `Key<P>`.
pub struct Bucket<P: BoxProvider + Send + Sync + Clone + 'static> {
    vaults: HashMap<Key<P>, Option<DBView<P>>>,
    cache: HashMap<Key<P>, Vec<ReadResult>>,
    store: Cache<Vec<u8>, Vec<u8>>,
}

impl<P: BoxProvider + Send + Sync + Clone + Ord + PartialOrd + PartialEq + Eq + 'static> Bucket<P> {
    /// Creates a new `Bucket`.
    pub fn new() -> Self {
        let cache = HashMap::new();
        let vaults = HashMap::new();
        let store = Cache::new();

        Self { cache, vaults, store }
    }

    #[allow(dead_code)]
    /// Gets the Vault `RecordIds` when given a `Key<P>`.  Returns a `Vec<RecordId>`.
    pub fn get_vault_record_ids(&mut self, key: Key<P>) -> Vec<RecordId> {
        let mut buffer = Vec::new();
        self.take(key, |view, reads| {
            let map = view.chain_ctrs();

            map.keys().into_iter().for_each(|rid| {
                buffer.push(*rid);
            });

            reads
        });

        buffer
    }

    /// Creates and initializes a new Vault given a `Key<P>`.  Returns a tuple of `(Key<P>, RecordId)`. The returned
    /// `Key<P>` is the Key associated with the Vault and the `RecordId` is the ID for its first record.
    pub fn create_and_init_vault(&mut self, key: Key<P>, rid: RecordId) -> RecordId {
        self.take(key, |view, mut reads| {
            let mut writer = view.writer(rid);

            let truncate = writer.truncate().expect(line_error!());

            reads.push(write_to_read(&truncate));

            reads
        });

        rid
    }

    /// Reads data from a Record in the Vault given a `RecordId`.  Returns the data as a `Vec<u8>` of utf8 bytes.
    pub fn read_data(&mut self, key: Key<P>, id: RecordId) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![];
        self.take(key, |view, reads| {
            let reader = view.reader();

            let res = reader.prepare_read(&id).expect(line_error!());

            if let PreparedRead::CacheHit(mut v) = res {
                buffer.append(&mut v);
            }

            reads
        });

        buffer
    }

    pub fn record_exists_in_vault(&mut self, key: Key<P>, rid: RecordId) -> bool {
        let mut res = false;

        self.take(key, |view, reads| {
            let reader = view.reader();

            res = reader.exists(rid);

            reads
        });

        res
    }

    /// Initializes a new Record in the Vault based on the inserted `Key<P>`. Returns a `RecordId` for the new Record.
    pub fn init_record(&mut self, key: Key<P>, rid: RecordId) -> RecordId {
        self.take(key, |view, mut reads| {
            let mut writer = view.writer(rid);

            let truncate = writer.truncate().expect(line_error!());

            reads.push(write_to_read(&truncate));

            reads
        });

        rid
    }

    /// Writes a payload of `Vec<u8>` and a `RecordHint` into a Record. Record is specified with the inserted `RecordId`
    /// and the `Key<P>`
    pub fn write_payload(&mut self, key: Key<P>, id: RecordId, payload: Vec<u8>, hint: RecordHint) {
        self.take(key, |view, mut reads| {
            let mut writer = view.writer(id);

            let writes = writer.write(&payload, hint).expect(line_error!());

            let mut results: Vec<ReadResult> = writes.into_iter().map(|w| write_to_read(&w)).collect();

            reads.append(&mut results);

            reads
        });
    }

    /// Marks a record for deletion based on a given `Key<P>` and `RecordId`
    pub fn revoke_data(&mut self, key: Key<P>, id: RecordId) {
        self.take(key, |view, mut reads| {
            let mut writer = view.writer(id);

            let revoke = writer.revoke().expect(line_error!());

            reads.push(write_to_read(&revoke));

            reads
        });
    }

    /// Garbage Collects any deletion marked Records in the given Vault. Accepts a `Key<P>`
    pub fn garbage_collect(&mut self, key: Key<P>) {
        self.take(key, |view, mut reads| {
            let deletes = view.gc();

            deletes.iter().for_each(|d| reads.retain(|r| r.id() != d.id()));

            reads
        });
    }

    /// Lists the `RecordId`s and `RecordHint`s for a given Vault.  Accepts a `Key<P>`
    pub fn list_ids(&mut self, key: Key<P>) -> Vec<(RecordId, RecordHint)> {
        let mut buffer: Vec<(RecordId, RecordHint)> = Vec::new();

        self.take(key, |view, reads| {
            let mut data = view.records().collect();

            buffer.append(&mut data);

            reads
        });

        buffer
    }

    /// Repopulates the data in the Bucket given a Vec<u8> of state from a snapshot.  Returns a `Vec<Key<P>,
    /// Vec<Vec<RecordId>>`.
    pub fn repopulate_data(&mut self, cache: HashMap<Key<P>, Vec<ReadResult>>) -> (Vec<Key<P>>, Vec<Vec<RecordId>>) {
        let mut vaults = HashMap::new();
        let mut rids: Vec<Vec<RecordId>> = Vec::new();
        let mut keystore_keys: Vec<Key<P>> = Vec::new();

        cache.clone().into_iter().for_each(|(k, v)| {
            keystore_keys.push(k.clone());
            let view = DBView::load(k.clone(), v.iter()).expect(line_error!());

            rids.push(view.all().collect());

            vaults.insert(k, Some(view));
        });

        self.vaults = vaults;
        self.cache = cache;

        (keystore_keys, rids)
    }

    /// Deserialize the data in the cache of the bucket into bytes to be passed into a snapshot.  Returns a `Vec<u8>`.
    pub fn offload_data(&mut self) -> Vec<u8> {
        let mut cache: HashMap<Key<P>, Vec<ReadResult>> = HashMap::new();

        self.cache.iter().for_each(|(k, v)| {
            cache.insert(k.clone(), v.clone());
        });

        bincode::serialize(&cache).expect(line_error!())
    }

    pub fn get_data(&mut self) -> HashMap<Key<P>, Vec<ReadResult>> {
        let mut cache: HashMap<Key<P>, Vec<ReadResult>> = HashMap::new();

        self.cache.iter().for_each(|(k, v)| {
            cache.insert(k.clone(), v.clone());
        });

        cache
    }

    /// Write unencrypted data to the store.  Returns `None` if the key didn't already exist and `Some(Vec<u8>)` if the
    /// key was updated.
    pub fn write_to_store(&mut self, key: Vec<u8>, data: Vec<u8>, lifetime: Option<Duration>) -> Option<Vec<u8>> {
        self.store.insert(key, data, lifetime)
    }

    /// Attempts to read the data from the store.  Returns `Some(Vec<u8>)` if the key exists and `None` if it doesn't.
    pub fn read_from_store(&mut self, key: Vec<u8>) -> Option<Vec<u8>> {
        let res = self.store.get(&key);

        if let Some(vec) = res {
            Some(vec.to_vec())
        } else {
            None
        }
    }

    /// Deletes an item from the store by the given key.
    pub fn store_delete_item(&mut self, key: Vec<u8>) {
        self.store.remove(&key);
    }

    /// Checks to see if the key exists in the store.
    pub fn store_key_exists(&mut self, key: Vec<u8>) -> bool {
        self.store.contains_key(&key)
    }

    pub fn clear_cache(&mut self) {
        self.vaults.clear();
        self.cache.clear();
        self.store.clear();
    }

    /// Exposes the `DBView` of the current vault and the cache layer to allow transactions to occur.
    fn take(&mut self, key: Key<P>, f: impl FnOnce(DBView<P>, Vec<ReadResult>) -> Vec<ReadResult>) {
        let mut _reads = self.get_reads(key.clone());
        let reads = _reads.take().expect(line_error!());
        let mut _view = self.get_view(key.clone(), reads.clone());
        let view = _view.take().expect(line_error!());
        let res = f(view, reads);
        self.insert_reads(key.clone(), res);
        self.insert_view(key, _view);
    }

    fn get_view(&mut self, key: Key<P>, reads: Vec<ReadResult>) -> Option<DBView<P>> {
        self.vaults.remove(&key);

        Some(DBView::load(key, reads.iter()).expect(line_error!()))
    }

    fn insert_view(&mut self, key: Key<P>, view: Option<DBView<P>>) {
        self.vaults.insert(key, view);
    }

    fn get_reads(&mut self, key: Key<P>) -> Option<Vec<ReadResult>> {
        match self.cache.remove(&key) {
            Some(reads) => Some(reads),
            None => Some(Vec::<ReadResult>::new()),
        }
    }

    fn insert_reads(&mut self, key: Key<P>, reads: Vec<ReadResult>) {
        self.cache.insert(key, reads);
    }
}

fn write_to_read(write: &WriteRequest) -> ReadResult {
    ReadResult::new(write.kind(), write.id(), write.data())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bucket() {
        use crate::Provider;

        let key1 = Key::<Provider>::random().expect(line_error!());
        let key2 = Key::<Provider>::random().expect(line_error!());

        let rid1 = RecordId::random::<Provider>().expect(line_error!());
        let rid2 = RecordId::random::<Provider>().expect(line_error!());

        let mut bucket = Bucket::<Provider>::new();

        let rid1 = bucket.create_and_init_vault(key1.clone(), rid1);
        let rid2 = bucket.create_and_init_vault(key2.clone(), rid2);
        println!("vault1 id1: {:?}", rid1);
        println!("vault2 id1: {:?}", rid2);

        bucket.write_payload(
            key1.clone(),
            rid1,
            b"some data".to_vec(),
            RecordHint::new(b"").expect(line_error!()),
        );

        bucket.write_payload(
            key2,
            rid2,
            b"some new data".to_vec(),
            RecordHint::new(b"").expect(line_error!()),
        );

        let rid3 = RecordId::random::<Provider>().expect(line_error!());
        let rid3 = bucket.init_record(key1.clone(), rid3);

        bucket.write_payload(
            key1.clone(),
            rid3,
            b"some more data".to_vec(),
            RecordHint::new(b"").expect(line_error!()),
        );

        println!("vault1 rid2: {:?}", rid3);

        let data = bucket.read_data(key1.clone(), rid1);
        println!("{:?}", std::str::from_utf8(&data));
        let data = bucket.read_data(key1, rid3);

        println!("{:?}", std::str::from_utf8(&data));
    }

    fn write_to_read(write: &WriteRequest) -> ReadResult {
        ReadResult::new(write.kind(), write.id(), write.data())
    }

    #[test]
    fn test_take() {
        use crate::Provider;

        let key = Key::<Provider>::random().expect(line_error!());

        let mut bucket = Bucket::<Provider>::new();
        let id1 = RecordId::random::<Provider>().expect(line_error!());
        let id2 = RecordId::random::<Provider>().expect(line_error!());

        bucket.take(key.clone(), |view, mut reads| -> Vec<ReadResult> {
            let mut writer = view.writer(id1);

            let wr = writer.truncate().expect(line_error!());

            reads.push(write_to_read(&wr));

            reads
        });

        bucket.take(key.clone(), |view, mut reads| {
            let mut writer = view.writer(id1);

            let wr = writer
                .write(b"some data", RecordHint::new(b"").expect(line_error!()))
                .expect(line_error!());

            let mut wr: Vec<ReadResult> = wr.into_iter().map(|w| write_to_read(&w)).collect();

            reads.append(&mut wr);

            reads
        });

        bucket.take(key.clone(), |view, mut reads| {
            let mut writer = view.writer(id2);

            let wr = writer.truncate().expect(line_error!());

            reads.push(write_to_read(&wr));

            reads
        });

        bucket.take(key.clone(), |view, reads| {
            let data: Vec<(RecordId, RecordHint)> = view.records().collect();

            data.iter().for_each(|(i, h)| {
                println!("{:?}: {:?}", i, h);
            });

            reads
        });

        bucket.take(key.clone(), |view, reads| {
            let reader = view.reader();

            let res = reader.prepare_read(&id1).expect(line_error!());

            match res {
                PreparedRead::CacheHit(v) => {
                    println!("{:?}", std::str::from_utf8(&v));
                }
                PreparedRead::CacheMiss(v) => {
                    println!("{:?}", v.id());
                }
                _ => {
                    println!("Record doesn't exist");
                }
            }

            reads
        });

        bucket.take(key.clone(), |view, mut reads| {
            let mut writer = view.writer(id1);

            reads.push(write_to_read(&writer.revoke().expect(line_error!())));

            reads
        });

        bucket.take(key.clone(), |view, mut reads| {
            let deletes = view.gc();

            deletes.iter().for_each(|d| {
                reads.retain(|r| r.id() != d.id());
            });

            reads
        });

        bucket.take(key, |view, reads| {
            let data: Vec<(RecordId, RecordHint)> = view.records().collect();

            data.iter().for_each(|(i, h)| {
                println!("Data {:?}: {:?}", i, h);
            });

            reads
        });

        println!("{:?}, {:?}", id1, id2);
    }
}
