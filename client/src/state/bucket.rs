// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use engine::{
    store::Cache,
    vault::{BoxProvider, DBView, GuardedData, Key, PreparedRead, ReadResult, RecordHint, RecordId, WriteRequest},
};

use std::collections::HashMap;

use crate::{line_error, VaultId};

type Store = Cache<Vec<u8>, Vec<u8>>;

/// A `Bucket` cache of the Data for stronghold. Contains a `HashMap<Key<P>, Option<DBView<P>>>` pairing the vault
/// `Key<P>` and the vault `DBView<P>` together. Also contains a `HashMap<Key<P>, Vec<ReadResult>>` which pairs the
/// backing data with the associated `Key<P>`.
pub struct Bucket {
    cache: HashMap<VaultId, Vec<GuardedData>>,
}

impl Bucket {
    /// Creates a new `Bucket`.
    pub fn new() -> Self {
        let cache = HashMap::new();

        Self { cache }
    }

    /// Creates and initializes a new Vault given a `Key<P>`.  Returns a tuple of `(Key<P>, RecordId)`. The returned
    /// `Key<P>` is the Key associated with the Vault and the `RecordId` is the ID for its first record.
    pub fn create_and_init_vault<P: BoxProvider>(&mut self, id: VaultId, key: Key<P>, rid: RecordId) -> RecordId {
        self.take(id, key, |view, mut reads| {
            let mut writer = view.writer(rid);

            let truncate = writer.truncate().expect(line_error!());

            reads.push(write_to_read(&truncate));

            reads
        });

        rid
    }

    /// Reads data from a Record in the Vault given a `RecordId`.  Returns the data as a `Vec<u8>` of utf8 bytes.
    pub fn read_data<P: BoxProvider>(&mut self, id: VaultId, key: Key<P>, rid: RecordId) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![];
        self.take(id, key, |view, reads| {
            let reader = view.reader();

            let res = reader.prepare_read(&rid).expect(line_error!());

            if let PreparedRead::CacheHit(mut v) = res {
                buffer.append(&mut v);
            }

            reads
        });

        buffer
    }

    pub fn record_exists_in_vault<P: BoxProvider>(&mut self, id: VaultId, key: Key<P>, rid: RecordId) -> bool {
        let mut res = false;

        self.take(id, key, |view, reads| {
            let reader = view.reader();

            res = reader.exists(rid);

            reads
        });

        res
    }

    /// Initializes a new Record in the Vault based on the inserted `Key<P>`. Returns a `RecordId` for the new Record.
    pub fn init_record<P: BoxProvider>(&mut self, id: VaultId, key: Key<P>, rid: RecordId) -> RecordId {
        self.take(id, key, |view, mut reads| {
            let mut writer = view.writer(rid);

            let truncate = writer.truncate().expect(line_error!());

            reads.push(write_to_read(&truncate));

            reads
        });

        rid
    }

    /// Writes a payload of `Vec<u8>` and a `RecordHint` into a Record. Record is specified with the inserted `RecordId`
    /// and the `Key<P>`
    pub fn write_payload<P: BoxProvider>(
        &mut self,
        id: VaultId,
        key: Key<P>,
        rid: RecordId,
        payload: Vec<u8>,
        hint: RecordHint,
    ) {
        self.take(id, key, |view, mut reads| {
            let mut writer = view.writer(rid);

            let writes = writer.write(&payload, hint).expect(line_error!());

            let mut results: Vec<ReadResult> = writes.into_iter().map(|w| write_to_read(&w)).collect();

            reads.append(&mut results);

            reads
        });
    }

    /// Marks a record for deletion based on a given `Key<P>` and `RecordId`
    pub fn revoke_data<P: BoxProvider>(&mut self, id: VaultId, key: Key<P>, rid: RecordId) {
        self.take(id, key, |view, mut reads| {
            let mut writer = view.writer(rid);

            let revoke = writer.revoke().expect(line_error!());

            reads.push(write_to_read(&revoke));

            reads
        });
    }

    /// Garbage Collects any deletion marked Records in the given Vault. Accepts a `Key<P>`
    pub fn garbage_collect<P: BoxProvider>(&mut self, id: VaultId, key: Key<P>) {
        self.take(id, key, |view, mut reads| {
            let deletes = view.gc();

            deletes.iter().for_each(|d| reads.retain(|r| r.id() != d.id()));

            reads
        });
    }

    /// Lists the `RecordId`s and `RecordHint`s for a given Vault.  Accepts a `Key<P>`
    pub fn list_ids<P: BoxProvider>(&mut self, id: VaultId, key: Key<P>) -> Vec<(RecordId, RecordHint)> {
        let mut buffer: Vec<(RecordId, RecordHint)> = Vec::new();

        self.take(id, key, |view, reads| {
            let mut data = view.records().collect();

            buffer.append(&mut data);

            reads
        });

        buffer
    }

    /// Repopulates the data in the Bucket given a Vec<u8> of state from a snapshot.
    pub fn repopulate_data(&mut self, cache: HashMap<VaultId, Vec<GuardedData>>) {
        self.cache = cache;
    }

    pub fn get_data(&mut self) -> HashMap<VaultId, Vec<GuardedData>> {
        let mut cache: HashMap<VaultId, Vec<GuardedData>> = HashMap::new();

        self.cache.iter().for_each(|(k, v)| {
            cache.insert(k.clone(), v.clone());
        });

        cache
    }

    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Exposes the `DBView` of the current vault and the cache layer to allow transactions to occur.
    fn take<P: BoxProvider>(
        &mut self,
        id: VaultId,
        key: Key<P>,
        f: impl FnOnce(DBView<P>, Vec<ReadResult>) -> Vec<ReadResult>,
    ) {
        let reads: Vec<ReadResult> = self.get_reads(id).into_iter().map(guarded_to_read).collect();

        let view = DBView::load(key.clone(), reads.iter()).expect(line_error!());

        let res = f(view, reads);
        let guards = res.into_iter().map(read_to_guarded).collect();

        self.insert_reads(id, guards);
    }

    fn get_reads(&mut self, id: VaultId) -> Vec<GuardedData> {
        match self.cache.remove(&id) {
            Some(reads) => reads,
            None => Vec::<GuardedData>::new(),
        }
    }

    fn insert_reads(&mut self, id: VaultId, reads: Vec<GuardedData>) {
        self.cache.insert(id, reads);
    }
}

fn write_to_read(write: &WriteRequest) -> ReadResult {
    ReadResult::new(write.kind(), write.id(), write.data())
}

fn read_to_guarded(read: ReadResult) -> GuardedData {
    read.into()
}

fn guarded_to_read(guard: GuardedData) -> ReadResult {
    guard.into()
}
