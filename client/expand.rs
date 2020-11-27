#![feature(prelude_import)]
#[prelude_import]
use std::prelude::v1::*;
#[macro_use]
extern crate std;
use thiserror::Error as DeriveError;
mod actors {
    use riker::actors::*;
    use std::{fmt::Debug, path::PathBuf};
    use engine::vault::{BoxProvider, Key, RecordHint, RecordId};
    use crate::{
        bucket::Bucket, client::ClientMsg, ids::VaultId, key_store::KeyStore, line_error,
        provider::Provider, snapshot::Snapshot,
    };
    pub enum BMsg<P: BoxProvider + Debug> {
        CreateVault(VaultId, Key<P>),
        ReadData(Key<P>, RecordId),
        WriteData(Key<P>, RecordId, Vec<u8>, RecordHint),
        InitRecord(Key<P>, VaultId),
        RevokeData(Key<P>, RecordId),
        GarbageCollect(Key<P>),
        ListAsk(Key<P>),
        WriteSnapshot(String, Option<PathBuf>),
        ReadSnapshot(String, Option<PathBuf>),
        ReloadData(Vec<u8>),
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl<P: ::core::fmt::Debug + BoxProvider + Debug> ::core::fmt::Debug for BMsg<P> {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            match (&*self,) {
                (&BMsg::CreateVault(ref __self_0, ref __self_1),) => {
                    let mut debug_trait_builder = f.debug_tuple("CreateVault");
                    let _ = debug_trait_builder.field(&&(*__self_0));
                    let _ = debug_trait_builder.field(&&(*__self_1));
                    debug_trait_builder.finish()
                }
                (&BMsg::ReadData(ref __self_0, ref __self_1),) => {
                    let mut debug_trait_builder = f.debug_tuple("ReadData");
                    let _ = debug_trait_builder.field(&&(*__self_0));
                    let _ = debug_trait_builder.field(&&(*__self_1));
                    debug_trait_builder.finish()
                }
                (&BMsg::WriteData(ref __self_0, ref __self_1, ref __self_2, ref __self_3),) => {
                    let mut debug_trait_builder = f.debug_tuple("WriteData");
                    let _ = debug_trait_builder.field(&&(*__self_0));
                    let _ = debug_trait_builder.field(&&(*__self_1));
                    let _ = debug_trait_builder.field(&&(*__self_2));
                    let _ = debug_trait_builder.field(&&(*__self_3));
                    debug_trait_builder.finish()
                }
                (&BMsg::InitRecord(ref __self_0, ref __self_1),) => {
                    let mut debug_trait_builder = f.debug_tuple("InitRecord");
                    let _ = debug_trait_builder.field(&&(*__self_0));
                    let _ = debug_trait_builder.field(&&(*__self_1));
                    debug_trait_builder.finish()
                }
                (&BMsg::RevokeData(ref __self_0, ref __self_1),) => {
                    let mut debug_trait_builder = f.debug_tuple("RevokeData");
                    let _ = debug_trait_builder.field(&&(*__self_0));
                    let _ = debug_trait_builder.field(&&(*__self_1));
                    debug_trait_builder.finish()
                }
                (&BMsg::GarbageCollect(ref __self_0),) => {
                    let mut debug_trait_builder = f.debug_tuple("GarbageCollect");
                    let _ = debug_trait_builder.field(&&(*__self_0));
                    debug_trait_builder.finish()
                }
                (&BMsg::ListAsk(ref __self_0),) => {
                    let mut debug_trait_builder = f.debug_tuple("ListAsk");
                    let _ = debug_trait_builder.field(&&(*__self_0));
                    debug_trait_builder.finish()
                }
                (&BMsg::WriteSnapshot(ref __self_0, ref __self_1),) => {
                    let mut debug_trait_builder = f.debug_tuple("WriteSnapshot");
                    let _ = debug_trait_builder.field(&&(*__self_0));
                    let _ = debug_trait_builder.field(&&(*__self_1));
                    debug_trait_builder.finish()
                }
                (&BMsg::ReadSnapshot(ref __self_0, ref __self_1),) => {
                    let mut debug_trait_builder = f.debug_tuple("ReadSnapshot");
                    let _ = debug_trait_builder.field(&&(*__self_0));
                    let _ = debug_trait_builder.field(&&(*__self_1));
                    debug_trait_builder.finish()
                }
                (&BMsg::ReloadData(ref __self_0),) => {
                    let mut debug_trait_builder = f.debug_tuple("ReloadData");
                    let _ = debug_trait_builder.field(&&(*__self_0));
                    debug_trait_builder.finish()
                }
            }
        }
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl<P: ::core::clone::Clone + BoxProvider + Debug> ::core::clone::Clone for BMsg<P> {
        #[inline]
        fn clone(&self) -> BMsg<P> {
            match (&*self,) {
                (&BMsg::CreateVault(ref __self_0, ref __self_1),) => BMsg::CreateVault(
                    ::core::clone::Clone::clone(&(*__self_0)),
                    ::core::clone::Clone::clone(&(*__self_1)),
                ),
                (&BMsg::ReadData(ref __self_0, ref __self_1),) => BMsg::ReadData(
                    ::core::clone::Clone::clone(&(*__self_0)),
                    ::core::clone::Clone::clone(&(*__self_1)),
                ),
                (&BMsg::WriteData(ref __self_0, ref __self_1, ref __self_2, ref __self_3),) => {
                    BMsg::WriteData(
                        ::core::clone::Clone::clone(&(*__self_0)),
                        ::core::clone::Clone::clone(&(*__self_1)),
                        ::core::clone::Clone::clone(&(*__self_2)),
                        ::core::clone::Clone::clone(&(*__self_3)),
                    )
                }
                (&BMsg::InitRecord(ref __self_0, ref __self_1),) => BMsg::InitRecord(
                    ::core::clone::Clone::clone(&(*__self_0)),
                    ::core::clone::Clone::clone(&(*__self_1)),
                ),
                (&BMsg::RevokeData(ref __self_0, ref __self_1),) => BMsg::RevokeData(
                    ::core::clone::Clone::clone(&(*__self_0)),
                    ::core::clone::Clone::clone(&(*__self_1)),
                ),
                (&BMsg::GarbageCollect(ref __self_0),) => {
                    BMsg::GarbageCollect(::core::clone::Clone::clone(&(*__self_0)))
                }
                (&BMsg::ListAsk(ref __self_0),) => {
                    BMsg::ListAsk(::core::clone::Clone::clone(&(*__self_0)))
                }
                (&BMsg::WriteSnapshot(ref __self_0, ref __self_1),) => BMsg::WriteSnapshot(
                    ::core::clone::Clone::clone(&(*__self_0)),
                    ::core::clone::Clone::clone(&(*__self_1)),
                ),
                (&BMsg::ReadSnapshot(ref __self_0, ref __self_1),) => BMsg::ReadSnapshot(
                    ::core::clone::Clone::clone(&(*__self_0)),
                    ::core::clone::Clone::clone(&(*__self_1)),
                ),
                (&BMsg::ReloadData(ref __self_0),) => {
                    BMsg::ReloadData(::core::clone::Clone::clone(&(*__self_0)))
                }
            }
        }
    }
    pub enum KMsg {
        CreateVault(VaultId),
        ReadData(VaultId, RecordId),
        WriteData(VaultId, RecordId, Vec<u8>, RecordHint),
        InitRecord(VaultId),
        RevokeData(VaultId, RecordId),
        GarbageCollect(VaultId),
        ListIds(VaultId),
        RebuildKeys(Vec<Key<Provider>>),
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::clone::Clone for KMsg {
        #[inline]
        fn clone(&self) -> KMsg {
            match (&*self,) {
                (&KMsg::CreateVault(ref __self_0),) => {
                    KMsg::CreateVault(::core::clone::Clone::clone(&(*__self_0)))
                }
                (&KMsg::ReadData(ref __self_0, ref __self_1),) => KMsg::ReadData(
                    ::core::clone::Clone::clone(&(*__self_0)),
                    ::core::clone::Clone::clone(&(*__self_1)),
                ),
                (&KMsg::WriteData(ref __self_0, ref __self_1, ref __self_2, ref __self_3),) => {
                    KMsg::WriteData(
                        ::core::clone::Clone::clone(&(*__self_0)),
                        ::core::clone::Clone::clone(&(*__self_1)),
                        ::core::clone::Clone::clone(&(*__self_2)),
                        ::core::clone::Clone::clone(&(*__self_3)),
                    )
                }
                (&KMsg::InitRecord(ref __self_0),) => {
                    KMsg::InitRecord(::core::clone::Clone::clone(&(*__self_0)))
                }
                (&KMsg::RevokeData(ref __self_0, ref __self_1),) => KMsg::RevokeData(
                    ::core::clone::Clone::clone(&(*__self_0)),
                    ::core::clone::Clone::clone(&(*__self_1)),
                ),
                (&KMsg::GarbageCollect(ref __self_0),) => {
                    KMsg::GarbageCollect(::core::clone::Clone::clone(&(*__self_0)))
                }
                (&KMsg::ListIds(ref __self_0),) => {
                    KMsg::ListIds(::core::clone::Clone::clone(&(*__self_0)))
                }
                (&KMsg::RebuildKeys(ref __self_0),) => {
                    KMsg::RebuildKeys(::core::clone::Clone::clone(&(*__self_0)))
                }
            }
        }
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::fmt::Debug for KMsg {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            match (&*self,) {
                (&KMsg::CreateVault(ref __self_0),) => {
                    let mut debug_trait_builder = f.debug_tuple("CreateVault");
                    let _ = debug_trait_builder.field(&&(*__self_0));
                    debug_trait_builder.finish()
                }
                (&KMsg::ReadData(ref __self_0, ref __self_1),) => {
                    let mut debug_trait_builder = f.debug_tuple("ReadData");
                    let _ = debug_trait_builder.field(&&(*__self_0));
                    let _ = debug_trait_builder.field(&&(*__self_1));
                    debug_trait_builder.finish()
                }
                (&KMsg::WriteData(ref __self_0, ref __self_1, ref __self_2, ref __self_3),) => {
                    let mut debug_trait_builder = f.debug_tuple("WriteData");
                    let _ = debug_trait_builder.field(&&(*__self_0));
                    let _ = debug_trait_builder.field(&&(*__self_1));
                    let _ = debug_trait_builder.field(&&(*__self_2));
                    let _ = debug_trait_builder.field(&&(*__self_3));
                    debug_trait_builder.finish()
                }
                (&KMsg::InitRecord(ref __self_0),) => {
                    let mut debug_trait_builder = f.debug_tuple("InitRecord");
                    let _ = debug_trait_builder.field(&&(*__self_0));
                    debug_trait_builder.finish()
                }
                (&KMsg::RevokeData(ref __self_0, ref __self_1),) => {
                    let mut debug_trait_builder = f.debug_tuple("RevokeData");
                    let _ = debug_trait_builder.field(&&(*__self_0));
                    let _ = debug_trait_builder.field(&&(*__self_1));
                    debug_trait_builder.finish()
                }
                (&KMsg::GarbageCollect(ref __self_0),) => {
                    let mut debug_trait_builder = f.debug_tuple("GarbageCollect");
                    let _ = debug_trait_builder.field(&&(*__self_0));
                    debug_trait_builder.finish()
                }
                (&KMsg::ListIds(ref __self_0),) => {
                    let mut debug_trait_builder = f.debug_tuple("ListIds");
                    let _ = debug_trait_builder.field(&&(*__self_0));
                    debug_trait_builder.finish()
                }
                (&KMsg::RebuildKeys(ref __self_0),) => {
                    let mut debug_trait_builder = f.debug_tuple("RebuildKeys");
                    let _ = debug_trait_builder.field(&&(*__self_0));
                    debug_trait_builder.finish()
                }
            }
        }
    }
    pub enum SMsg {
        WriteSnapshot(String, Option<PathBuf>, Vec<u8>),
        ReadSnapshot(String, Option<PathBuf>),
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::clone::Clone for SMsg {
        #[inline]
        fn clone(&self) -> SMsg {
            match (&*self,) {
                (&SMsg::WriteSnapshot(ref __self_0, ref __self_1, ref __self_2),) => {
                    SMsg::WriteSnapshot(
                        ::core::clone::Clone::clone(&(*__self_0)),
                        ::core::clone::Clone::clone(&(*__self_1)),
                        ::core::clone::Clone::clone(&(*__self_2)),
                    )
                }
                (&SMsg::ReadSnapshot(ref __self_0, ref __self_1),) => SMsg::ReadSnapshot(
                    ::core::clone::Clone::clone(&(*__self_0)),
                    ::core::clone::Clone::clone(&(*__self_1)),
                ),
            }
        }
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::fmt::Debug for SMsg {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            match (&*self,) {
                (&SMsg::WriteSnapshot(ref __self_0, ref __self_1, ref __self_2),) => {
                    let mut debug_trait_builder = f.debug_tuple("WriteSnapshot");
                    let _ = debug_trait_builder.field(&&(*__self_0));
                    let _ = debug_trait_builder.field(&&(*__self_1));
                    let _ = debug_trait_builder.field(&&(*__self_2));
                    debug_trait_builder.finish()
                }
                (&SMsg::ReadSnapshot(ref __self_0, ref __self_1),) => {
                    let mut debug_trait_builder = f.debug_tuple("ReadSnapshot");
                    let _ = debug_trait_builder.field(&&(*__self_0));
                    let _ = debug_trait_builder.field(&&(*__self_1));
                    debug_trait_builder.finish()
                }
            }
        }
    }
    impl ActorFactory for Bucket<Provider> {
        fn create() -> Self {
            Bucket::new()
        }
    }
    impl ActorFactory for KeyStore<Provider> {
        fn create() -> Self {
            KeyStore::new()
        }
    }
    impl ActorFactory for Snapshot {
        fn create() -> Self {
            Snapshot::new::<Provider>(::alloc::vec::Vec::new())
        }
    }
    impl Actor for Bucket<Provider> {
        type Msg = BMsg<Provider>;
        fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
            self.receive(ctx, msg, sender);
        }
    }
    impl Actor for KeyStore<Provider> {
        type Msg = KMsg;
        fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
            self.receive(ctx, msg, sender);
        }
    }
    impl Actor for Snapshot {
        type Msg = SMsg;
        fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
            self.receive(ctx, msg, sender);
        }
    }
    impl Receive<SMsg> for Snapshot {
        type Msg = SMsg;
        fn receive(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, _sender: Sender) {
            match msg {
                SMsg::WriteSnapshot(pass, path, state) => {
                    let snapshot = Snapshot::new::<Provider>(state);
                    let path = if let Some(p) = path {
                        p
                    } else {
                        Snapshot::get_snapshot_path()
                    };
                    snapshot.write_to_snapshot(&path, &pass);
                }
                SMsg::ReadSnapshot(pass, path) => {
                    let path = if let Some(p) = path {
                        p
                    } else {
                        Snapshot::get_snapshot_path()
                    };
                    let snapshot = Snapshot::read_from_snapshot::<Provider>(&path, &pass);
                    let bucket = ctx
                        .select("/user/bucket/")
                        .expect("Error at src\\actors.rs:111");
                    bucket.try_tell(BMsg::ReloadData::<Provider>(snapshot.get_state()), None);
                }
            }
        }
    }
    impl Receive<BMsg<Provider>> for Bucket<Provider> {
        type Msg = BMsg<Provider>;
        fn receive(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, _sender: Sender) {
            match msg {
                BMsg::CreateVault(vid, key) => {
                    let (_, rid) = self.create_and_init_vault(key);
                    let client = ctx
                        .select("/user/client/")
                        .expect("Error at src\\actors.rs:126");
                }
                BMsg::ReadData(key, rid) => {
                    let plain = self.read_data(key, rid);
                    let client = ctx
                        .select("/user/client/")
                        .expect("Error at src\\actors.rs:132");
                }
                BMsg::WriteData(key, rid, payload, hint) => {
                    self.write_payload(key, rid, payload, hint);
                }
                BMsg::InitRecord(key, vid) => {
                    let rid = self.init_record(key);
                    let client = ctx
                        .select("/user/client/")
                        .expect("Error at src\\actors.rs:141");
                }
                BMsg::RevokeData(key, rid) => {
                    self.revoke_data(key, rid);
                }
                BMsg::GarbageCollect(key) => {
                    self.garbage_collect(key);
                }
                BMsg::ListAsk(key) => {
                    let ids = self.list_ids(key);
                    let client = ctx
                        .select("/user/client/")
                        .expect("Error at src\\actors.rs:153");
                }
                BMsg::WriteSnapshot(pass, path) => {
                    let state = self.offload_data();
                    let snapshot = ctx
                        .select("/user/snapshot/")
                        .expect("Error at src\\actors.rs:159");
                    snapshot.try_tell(SMsg::WriteSnapshot(pass, path, state), None);
                }
                BMsg::ReadSnapshot(pass, path) => {
                    let snapshot = ctx
                        .select("/user/snapshot/")
                        .expect("Error at src\\actors.rs:163");
                    snapshot.try_tell(SMsg::ReadSnapshot(pass, path), None);
                }
                BMsg::ReloadData(state) => {
                    let keys = self.repopulate_data(state);
                    let keystore = ctx
                        .select("/user/keystore/")
                        .expect("Error at src\\actors.rs:169");
                    keystore.try_tell(KMsg::RebuildKeys(keys), None);
                }
            }
        }
    }
    impl Receive<KMsg> for KeyStore<Provider> {
        type Msg = KMsg;
        fn receive(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, _sender: Sender) {
            match msg {
                KMsg::CreateVault(vid) => {
                    let key = self.create_key(vid);
                    let bucket = ctx
                        .select("/user/bucket/")
                        .expect("Error at src\\actors.rs:184");
                    bucket.try_tell(BMsg::CreateVault(vid, key), None);
                }
                KMsg::ReadData(vid, rid) => {
                    if let Some(key) = self.get_key(vid) {
                        let bucket = ctx
                            .select("/user/bucket/")
                            .expect("Error at src\\actors.rs:189");
                        bucket.try_tell(BMsg::ReadData(key.clone(), rid), None);
                        self.insert_key(vid, key);
                    }
                }
                KMsg::WriteData(vid, rid, payload, hint) => {
                    if let Some(key) = self.get_key(vid) {
                        let bucket = ctx
                            .select("/user/bucket/")
                            .expect("Error at src\\actors.rs:197");
                        bucket.try_tell(BMsg::WriteData(key.clone(), rid, payload, hint), None);
                        self.insert_key(vid, key);
                    }
                }
                KMsg::InitRecord(vid) => {
                    if let Some(key) = self.get_key(vid) {
                        let bucket = ctx
                            .select("/user/bucket/")
                            .expect("Error at src\\actors.rs:205");
                        bucket.try_tell(BMsg::InitRecord(key.clone(), vid), None);
                        self.insert_key(vid, key);
                    }
                }
                KMsg::RevokeData(vid, rid) => {
                    if let Some(key) = self.get_key(vid) {
                        let bucket = ctx
                            .select("/user/bucket/")
                            .expect("Error at src\\actors.rs:213");
                        bucket.try_tell(BMsg::RevokeData(key.clone(), rid), None);
                        self.insert_key(vid, key);
                    }
                }
                KMsg::GarbageCollect(vid) => {
                    if let Some(key) = self.get_key(vid) {
                        let bucket = ctx
                            .select("/user/bucket/")
                            .expect("Error at src\\actors.rs:221");
                        bucket.try_tell(BMsg::GarbageCollect(key.clone()), None);
                        self.insert_key(vid, key);
                    }
                }
                KMsg::ListIds(vid) => {
                    if let Some(key) = self.get_key(vid) {
                        let bucket = ctx
                            .select("/user/bucket/")
                            .expect("Error at src\\actors.rs:229");
                        bucket.try_tell(BMsg::ListAsk(key.clone()), None);
                        self.insert_key(vid, key);
                    }
                }
                KMsg::RebuildKeys(keys) => {
                    self.rebuild_keystore(keys);
                }
            }
        }
    }
}
mod bucket {
    use engine::vault::{
        BoxProvider, DBView, Key, PreparedRead, ReadResult, RecordHint, RecordId, WriteRequest,
    };
    use std::collections::HashMap;
    use crate::line_error;
    pub struct Bucket<P: BoxProvider + Send + Sync + Clone + 'static> {
        vaults: HashMap<Key<P>, Option<DBView<P>>>,
        cache: HashMap<Key<P>, Vec<ReadResult>>,
    }
    impl<P: BoxProvider + Send + Sync + Clone + 'static> Bucket<P> {
        pub fn new() -> Self {
            let cache = HashMap::new();
            let vaults = HashMap::new();
            Self { cache, vaults }
        }
        pub fn get_vault_recordids(&mut self, key: Key<P>) -> Vec<RecordId> {
            let mut buffer = Vec::new();
            self.take(key.clone(), |view, reads| {
                let map = view.chain_ctrs();
                map.keys().into_iter().for_each(|rid| {
                    buffer.push(*rid);
                });
                reads
            });
            buffer
        }
        pub fn create_and_init_vault(&mut self, key: Key<P>) -> (Key<P>, RecordId) {
            let id = RecordId::random::<P>().expect("Error at src\\bucket.rs:39");
            self.take(key.clone(), |view, mut reads| {
                let mut writer = view.writer(id);
                let truncate = writer.truncate().expect("Error at src\\bucket.rs:44");
                reads.push(write_to_read(&truncate));
                reads
            });
            (key, id)
        }
        pub fn read_data(&mut self, key: Key<P>, id: RecordId) -> Vec<u8> {
            let mut buffer: Vec<u8> = ::alloc::vec::Vec::new();
            self.take(key, |view, reads| {
                let reader = view.reader();
                let res = reader
                    .prepare_read(&id)
                    .expect("Error at src\\bucket.rs:59");
                match res {
                    PreparedRead::CacheHit(mut v) => {
                        buffer.append(&mut v);
                    }
                    PreparedRead::CacheMiss(v) => {
                        {
                            ::std::io::_print(::core::fmt::Arguments::new_v1(
                                &["", "\n"],
                                &match (&v.id(),) {
                                    (arg0,) => [::core::fmt::ArgumentV1::new(
                                        arg0,
                                        ::core::fmt::Debug::fmt,
                                    )],
                                },
                            ));
                        };
                    }
                    _ => {
                        {
                            ::std::io::_print(::core::fmt::Arguments::new_v1(
                                &["no data\n"],
                                &match () {
                                    () => [],
                                },
                            ));
                        };
                    }
                }
                reads
            });
            buffer
        }
        pub fn init_record(&mut self, key: Key<P>) -> RecordId {
            let id = RecordId::random::<P>().expect("Error at src\\bucket.rs:80");
            self.take(key, |view, mut reads| {
                let mut writer = view.writer(id);
                let truncate = writer.truncate().expect("Error at src\\bucket.rs:84");
                reads.push(write_to_read(&truncate));
                reads
            });
            id
        }
        pub fn write_payload(
            &mut self,
            key: Key<P>,
            id: RecordId,
            payload: Vec<u8>,
            hint: RecordHint,
        ) {
            self.take(key, |view, mut reads| {
                let mut writer = view.writer(id);
                let writes = writer
                    .write(&payload, hint)
                    .expect("Error at src\\bucket.rs:98");
                let mut results: Vec<ReadResult> =
                    writes.into_iter().map(|w| write_to_read(&w)).collect();
                reads.append(&mut results);
                reads
            });
        }
        pub fn revoke_data(&mut self, key: Key<P>, id: RecordId) {
            self.take(key, |view, mut reads| {
                let mut writer = view.writer(id);
                let revoke = writer.revoke().expect("Error at src\\bucket.rs:112");
                reads.push(write_to_read(&revoke));
                reads
            });
        }
        pub fn garbage_collect(&mut self, key: Key<P>) {
            self.take(key, |view, mut reads| {
                let deletes = view.gc();
                deletes
                    .iter()
                    .for_each(|d| reads.retain(|r| r.id() != d.id()));
                reads
            });
        }
        pub fn list_ids(&mut self, key: Key<P>) -> Vec<(RecordId, RecordHint)> {
            let mut buffer: Vec<(RecordId, RecordHint)> = Vec::new();
            self.take(key, |view, reads| {
                let mut data = view.records().collect();
                buffer.append(&mut data);
                reads
            });
            buffer
        }
        fn take(
            &mut self,
            key: Key<P>,
            f: impl FnOnce(DBView<P>, Vec<ReadResult>) -> Vec<ReadResult>,
        ) {
            let mut _reads = self.get_reads(key.clone());
            let reads = _reads.take().expect("Error at src\\bucket.rs:146");
            let mut _view = self.get_view(key.clone(), reads.clone());
            let view = _view.take().expect("Error at src\\bucket.rs:148");
            let res = f(view, reads);
            self.insert_reads(key.clone(), res);
            self.insert_view(key.clone(), _view);
        }
        fn get_view(&mut self, key: Key<P>, reads: Vec<ReadResult>) -> Option<DBView<P>> {
            self.vaults.remove(&key.clone());
            Some(DBView::load(key, reads.iter()).expect("Error at src\\bucket.rs:157"))
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
        pub fn offload_data(&mut self) -> Vec<u8> {
            let mut cache: HashMap<Key<P>, Vec<ReadResult>> = HashMap::new();
            self.cache.iter().for_each(|(k, v)| {
                cache.insert(k.clone(), v.clone());
            });
            bincode::serialize(&cache).expect("Error at src\\bucket.rs:182")
        }
        pub fn repopulate_data(&mut self, state: Vec<u8>) -> Vec<Key<P>> {
            let mut vaults = HashMap::new();
            let mut cache = HashMap::new();
            let mut keystore_keys: Vec<Key<P>> = Vec::new();
            let state: HashMap<Key<P>, Vec<ReadResult>> =
                bincode::deserialize(&state).expect("Error at src\\bucket.rs:190");
            state.into_iter().for_each(|(k, v)| {
                keystore_keys.push(k.clone());
                let view =
                    Some(DBView::load(k.clone(), v.iter()).expect("Error at src\\bucket.rs:194"));
                vaults.insert(k.clone(), view);
                cache.insert(k, v);
            });
            self.cache = cache;
            self.vaults = vaults;
            keystore_keys
        }
    }
    fn write_to_read(write: &WriteRequest) -> ReadResult {
        ReadResult::new(write.kind(), write.id(), write.data())
    }
}
mod client {
    use crate::{
        actors::KMsg,
        ids::{ClientId, VaultId},
        line_error,
        provider::Provider,
    };
    use std::path::PathBuf;
    use engine::vault::{RecordHint, RecordId};
    use riker::actors::*;
    use std::collections::HashMap;
    /// Implement Client in cache App.
    pub struct Client {
        id: ClientId,
        vaults: HashMap<VaultId, (usize, Vec<RecordId>)>,
        heads: Vec<RecordId>,
        index: Vec<VaultId>,
        chan: ChannelRef<ExternalResults>,
    }
    pub enum ClientMsg {
        SHResponses(SHResponses),
        SHResults(SHResults),
        ExternalResults(ExternalResults),
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::clone::Clone for ClientMsg {
        #[inline]
        fn clone(&self) -> ClientMsg {
            match (&*self,) {
                (&ClientMsg::SHResponses(ref __self_0),) => {
                    ClientMsg::SHResponses(::core::clone::Clone::clone(&(*__self_0)))
                }
                (&ClientMsg::SHResults(ref __self_0),) => {
                    ClientMsg::SHResults(::core::clone::Clone::clone(&(*__self_0)))
                }
                (&ClientMsg::ExternalResults(ref __self_0),) => {
                    ClientMsg::ExternalResults(::core::clone::Clone::clone(&(*__self_0)))
                }
            }
        }
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::fmt::Debug for ClientMsg {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            match (&*self,) {
                (&ClientMsg::SHResponses(ref __self_0),) => {
                    let mut debug_trait_builder = f.debug_tuple("SHResponses");
                    let _ = debug_trait_builder.field(&&(*__self_0));
                    debug_trait_builder.finish()
                }
                (&ClientMsg::SHResults(ref __self_0),) => {
                    let mut debug_trait_builder = f.debug_tuple("SHResults");
                    let _ = debug_trait_builder.field(&&(*__self_0));
                    debug_trait_builder.finish()
                }
                (&ClientMsg::ExternalResults(ref __self_0),) => {
                    let mut debug_trait_builder = f.debug_tuple("ExternalResults");
                    let _ = debug_trait_builder.field(&&(*__self_0));
                    debug_trait_builder.finish()
                }
            }
        }
    }
    impl Into<ClientMsg> for SHResponses {
        fn into(self) -> ClientMsg {
            ClientMsg::SHResponses(self)
        }
    }
    impl Into<ClientMsg> for SHResults {
        fn into(self) -> ClientMsg {
            ClientMsg::SHResults(self)
        }
    }
    impl Into<ClientMsg> for ExternalResults {
        fn into(self) -> ClientMsg {
            ClientMsg::ExternalResults(self)
        }
    }
    impl Receive<ClientMsg> for Client {
        type Msg = ClientMsg;
        fn receive(
            &mut self,
            ctx: &Context<Self::Msg>,
            msg: ClientMsg,
            sender: Option<BasicActorRef>,
        ) {
            match msg {
                ClientMsg::SHResponses(msg) => <Client>::receive(self, ctx, msg, sender),
                ClientMsg::SHResults(msg) => <Client>::receive(self, ctx, msg, sender),
                ClientMsg::ExternalResults(msg) => <Client>::receive(self, ctx, msg, sender),
            }
        }
    }
    pub struct SHResponses {
        create_vault: Option<()>,
        write_data: Option<(usize, Vec<u8>, RecordHint)>,
        init_record: Option<usize>,
        read_data: Option<usize>,
        revoke_Data: Option<usize>,
        garbage_collect: Option<usize>,
        list_ids: Option<usize>,
        write_snapshot: Option<(String, Option<PathBuf>)>,
        read_snapshot: Option<(String, Option<PathBuf>)>,
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::fmt::Debug for SHResponses {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            match *self {
                SHResponses {
                    create_vault: ref __self_0_0,
                    write_data: ref __self_0_1,
                    init_record: ref __self_0_2,
                    read_data: ref __self_0_3,
                    revoke_Data: ref __self_0_4,
                    garbage_collect: ref __self_0_5,
                    list_ids: ref __self_0_6,
                    write_snapshot: ref __self_0_7,
                    read_snapshot: ref __self_0_8,
                } => {
                    let mut debug_trait_builder = f.debug_struct("SHResponses");
                    let _ = debug_trait_builder.field("create_vault", &&(*__self_0_0));
                    let _ = debug_trait_builder.field("write_data", &&(*__self_0_1));
                    let _ = debug_trait_builder.field("init_record", &&(*__self_0_2));
                    let _ = debug_trait_builder.field("read_data", &&(*__self_0_3));
                    let _ = debug_trait_builder.field("revoke_Data", &&(*__self_0_4));
                    let _ = debug_trait_builder.field("garbage_collect", &&(*__self_0_5));
                    let _ = debug_trait_builder.field("list_ids", &&(*__self_0_6));
                    let _ = debug_trait_builder.field("write_snapshot", &&(*__self_0_7));
                    let _ = debug_trait_builder.field("read_snapshot", &&(*__self_0_8));
                    debug_trait_builder.finish()
                }
            }
        }
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::clone::Clone for SHResponses {
        #[inline]
        fn clone(&self) -> SHResponses {
            match *self {
                SHResponses {
                    create_vault: ref __self_0_0,
                    write_data: ref __self_0_1,
                    init_record: ref __self_0_2,
                    read_data: ref __self_0_3,
                    revoke_Data: ref __self_0_4,
                    garbage_collect: ref __self_0_5,
                    list_ids: ref __self_0_6,
                    write_snapshot: ref __self_0_7,
                    read_snapshot: ref __self_0_8,
                } => SHResponses {
                    create_vault: ::core::clone::Clone::clone(&(*__self_0_0)),
                    write_data: ::core::clone::Clone::clone(&(*__self_0_1)),
                    init_record: ::core::clone::Clone::clone(&(*__self_0_2)),
                    read_data: ::core::clone::Clone::clone(&(*__self_0_3)),
                    revoke_Data: ::core::clone::Clone::clone(&(*__self_0_4)),
                    garbage_collect: ::core::clone::Clone::clone(&(*__self_0_5)),
                    list_ids: ::core::clone::Clone::clone(&(*__self_0_6)),
                    write_snapshot: ::core::clone::Clone::clone(&(*__self_0_7)),
                    read_snapshot: ::core::clone::Clone::clone(&(*__self_0_8)),
                },
            }
        }
    }
    pub struct SHResults {
        return_create: Option<(VaultId, RecordId)>,
        return_init: Option<usize>,
        return_read: Option<Vec<u8>>,
        read_list: Option<Vec<(RecordId, RecordHint)>>,
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::fmt::Debug for SHResults {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            match *self {
                SHResults {
                    return_create: ref __self_0_0,
                    return_init: ref __self_0_1,
                    return_read: ref __self_0_2,
                    read_list: ref __self_0_3,
                } => {
                    let mut debug_trait_builder = f.debug_struct("SHResults");
                    let _ = debug_trait_builder.field("return_create", &&(*__self_0_0));
                    let _ = debug_trait_builder.field("return_init", &&(*__self_0_1));
                    let _ = debug_trait_builder.field("return_read", &&(*__self_0_2));
                    let _ = debug_trait_builder.field("read_list", &&(*__self_0_3));
                    debug_trait_builder.finish()
                }
            }
        }
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::clone::Clone for SHResults {
        #[inline]
        fn clone(&self) -> SHResults {
            match *self {
                SHResults {
                    return_create: ref __self_0_0,
                    return_init: ref __self_0_1,
                    return_read: ref __self_0_2,
                    read_list: ref __self_0_3,
                } => SHResults {
                    return_create: ::core::clone::Clone::clone(&(*__self_0_0)),
                    return_init: ::core::clone::Clone::clone(&(*__self_0_1)),
                    return_read: ::core::clone::Clone::clone(&(*__self_0_2)),
                    read_list: ::core::clone::Clone::clone(&(*__self_0_3)),
                },
            }
        }
    }
    pub struct ExternalResults {}
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::clone::Clone for ExternalResults {
        #[inline]
        fn clone(&self) -> ExternalResults {
            match *self {
                ExternalResults {} => ExternalResults {},
            }
        }
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::fmt::Debug for ExternalResults {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            match *self {
                ExternalResults {} => {
                    let mut debug_trait_builder = f.debug_struct("ExternalResults");
                    debug_trait_builder.finish()
                }
            }
        }
    }
    /// Create a new Client.
    impl Client {
        pub fn new(id: ClientId, chan: ChannelRef<ExternalResults>) -> Self {
            let vaults = HashMap::new();
            let heads = Vec::new();
            let index = Vec::new();
            Self {
                id,
                vaults,
                heads,
                index,
                chan,
            }
        }
        pub fn add_vault(&mut self, vid: VaultId, rid: RecordId) {
            self.heads.push(rid);
            self.index.push(vid);
            let idx = self.index.len() - 1;
            self.vaults.insert(vid, (idx, <[_]>::into_vec(box [rid])));
        }
        pub fn insert_record(&mut self, vid: VaultId, rid: RecordId) {
            let mut heads: Vec<RecordId> = self.heads.clone();
            let mut index: Vec<VaultId> = self.index.clone();
            let (idx, rids) = self
                .vaults
                .entry(vid)
                .and_modify(|(idx, rids)| {
                    rids.push(rid);
                    if heads.len() <= *idx {
                        heads.push(rid);
                    } else {
                        heads[*idx] = rid;
                    }
                })
                .or_insert((0, <[_]>::into_vec(box [rid])));
            if !heads.contains(&rid) {
                heads.push(rid);
            }
            if !index.contains(&vid) {
                index.push(vid);
            }
            self.index = index;
            self.heads = heads;
        }
        pub fn get_head(&self, index: usize) -> Option<RecordId> {
            if self.heads.len() <= index {
                None
            } else {
                Some(self.heads[index])
            }
        }
        pub fn get_vault(&self, index: usize) -> Option<VaultId> {
            if self.index.len() <= index {
                None
            } else {
                Some(self.index[index])
            }
        }
        pub fn get_index(&self, vid: VaultId) -> Option<usize> {
            if self.vaults.contains_key(&vid) {
                let (idx, _) = self.vaults.get(&vid).expect("Error at src\\client.rs:149");
                Some(*idx)
            } else {
                None
            }
        }
    }
    /// Actor Factor for the Client Struct.
    impl ActorFactoryArgs<ChannelRef<ExternalResults>> for Client {
        fn create_args(chan: ChannelRef<ExternalResults>) -> Self {
            Client::new(
                ClientId::random::<Provider>().expect("Error at src\\client.rs:161"),
                chan,
            )
        }
    }
    /// Actor implementation for the Client.
    impl Actor for Client {
        type Msg = ClientMsg;
        fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
            self.receive(ctx, msg, sender);
        }
    }
    /// Client Receive Block.
    impl Receive<SHResponses> for Client {
        type Msg = ClientMsg;
        fn receive(&mut self, ctx: &Context<Self::Msg>, msg: SHResponses, _sender: Sender) {}
    }
    impl Receive<SHResults> for Client {
        type Msg = ClientMsg;
        fn receive(&mut self, ctx: &Context<Self::Msg>, msg: SHResults, _sender: Sender) {}
    }
    /// Client Receive Block.
    impl Receive<ExternalResults> for Client {
        type Msg = ClientMsg;
        fn receive(&mut self, ctx: &Context<Self::Msg>, msg: ExternalResults, _sender: Sender) {}
    }
}
mod ids {
    use serde::{Deserialize, Serialize};
    use engine::vault::{Base64Encodable, BoxProvider};
    use std::{
        convert::{TryFrom, TryInto},
        fmt::{self, Debug, Formatter},
        hash::Hash,
    };
    #[repr(transparent)]
    pub struct ClientId(ID);
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::marker::Copy for ClientId {}
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::clone::Clone for ClientId {
        #[inline]
        fn clone(&self) -> ClientId {
            {
                let _: ::core::clone::AssertParamIsClone<ID>;
                *self
            }
        }
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::hash::Hash for ClientId {
        fn hash<__H: ::core::hash::Hasher>(&self, state: &mut __H) -> () {
            match *self {
                ClientId(ref __self_0_0) => ::core::hash::Hash::hash(&(*__self_0_0), state),
            }
        }
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::cmp::Ord for ClientId {
        #[inline]
        fn cmp(&self, other: &ClientId) -> ::core::cmp::Ordering {
            match *other {
                ClientId(ref __self_1_0) => match *self {
                    ClientId(ref __self_0_0) => {
                        match ::core::cmp::Ord::cmp(&(*__self_0_0), &(*__self_1_0)) {
                            ::core::cmp::Ordering::Equal => ::core::cmp::Ordering::Equal,
                            cmp => cmp,
                        }
                    }
                },
            }
        }
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::cmp::PartialOrd for ClientId {
        #[inline]
        fn partial_cmp(&self, other: &ClientId) -> ::core::option::Option<::core::cmp::Ordering> {
            match *other {
                ClientId(ref __self_1_0) => match *self {
                    ClientId(ref __self_0_0) => {
                        match ::core::cmp::PartialOrd::partial_cmp(&(*__self_0_0), &(*__self_1_0)) {
                            ::core::option::Option::Some(::core::cmp::Ordering::Equal) => {
                                ::core::option::Option::Some(::core::cmp::Ordering::Equal)
                            }
                            cmp => cmp,
                        }
                    }
                },
            }
        }
        #[inline]
        fn lt(&self, other: &ClientId) -> bool {
            match *other {
                ClientId(ref __self_1_0) => match *self {
                    ClientId(ref __self_0_0) => {
                        ::core::option::Option::unwrap_or(
                            ::core::cmp::PartialOrd::partial_cmp(&(*__self_0_0), &(*__self_1_0)),
                            ::core::cmp::Ordering::Greater,
                        ) == ::core::cmp::Ordering::Less
                    }
                },
            }
        }
        #[inline]
        fn le(&self, other: &ClientId) -> bool {
            match *other {
                ClientId(ref __self_1_0) => match *self {
                    ClientId(ref __self_0_0) => {
                        ::core::option::Option::unwrap_or(
                            ::core::cmp::PartialOrd::partial_cmp(&(*__self_0_0), &(*__self_1_0)),
                            ::core::cmp::Ordering::Greater,
                        ) != ::core::cmp::Ordering::Greater
                    }
                },
            }
        }
        #[inline]
        fn gt(&self, other: &ClientId) -> bool {
            match *other {
                ClientId(ref __self_1_0) => match *self {
                    ClientId(ref __self_0_0) => {
                        ::core::option::Option::unwrap_or(
                            ::core::cmp::PartialOrd::partial_cmp(&(*__self_0_0), &(*__self_1_0)),
                            ::core::cmp::Ordering::Less,
                        ) == ::core::cmp::Ordering::Greater
                    }
                },
            }
        }
        #[inline]
        fn ge(&self, other: &ClientId) -> bool {
            match *other {
                ClientId(ref __self_1_0) => match *self {
                    ClientId(ref __self_0_0) => {
                        ::core::option::Option::unwrap_or(
                            ::core::cmp::PartialOrd::partial_cmp(&(*__self_0_0), &(*__self_1_0)),
                            ::core::cmp::Ordering::Less,
                        ) != ::core::cmp::Ordering::Less
                    }
                },
            }
        }
    }
    impl ::core::marker::StructuralEq for ClientId {}
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::cmp::Eq for ClientId {
        #[inline]
        #[doc(hidden)]
        fn assert_receiver_is_total_eq(&self) -> () {
            {
                let _: ::core::cmp::AssertParamIsEq<ID>;
            }
        }
    }
    impl ::core::marker::StructuralPartialEq for ClientId {}
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::cmp::PartialEq for ClientId {
        #[inline]
        fn eq(&self, other: &ClientId) -> bool {
            match *other {
                ClientId(ref __self_1_0) => match *self {
                    ClientId(ref __self_0_0) => (*__self_0_0) == (*__self_1_0),
                },
            }
        }
        #[inline]
        fn ne(&self, other: &ClientId) -> bool {
            match *other {
                ClientId(ref __self_1_0) => match *self {
                    ClientId(ref __self_0_0) => (*__self_0_0) != (*__self_1_0),
                },
            }
        }
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(rust_2018_idioms, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl _serde::Serialize for ClientId {
            fn serialize<__S>(
                &self,
                __serializer: __S,
            ) -> _serde::export::Result<__S::Ok, __S::Error>
            where
                __S: _serde::Serializer,
            {
                _serde::Serializer::serialize_newtype_struct(__serializer, "ClientId", &self.0)
            }
        }
    };
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(rust_2018_idioms, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl<'de> _serde::Deserialize<'de> for ClientId {
            fn deserialize<__D>(__deserializer: __D) -> _serde::export::Result<Self, __D::Error>
            where
                __D: _serde::Deserializer<'de>,
            {
                struct __Visitor<'de> {
                    marker: _serde::export::PhantomData<ClientId>,
                    lifetime: _serde::export::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = ClientId;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::export::Formatter,
                    ) -> _serde::export::fmt::Result {
                        _serde::export::Formatter::write_str(__formatter, "tuple struct ClientId")
                    }
                    #[inline]
                    fn visit_newtype_struct<__E>(
                        self,
                        __e: __E,
                    ) -> _serde::export::Result<Self::Value, __E::Error>
                    where
                        __E: _serde::Deserializer<'de>,
                    {
                        let __field0: ID = match <ID as _serde::Deserialize>::deserialize(__e) {
                            _serde::export::Ok(__val) => __val,
                            _serde::export::Err(__err) => {
                                return _serde::export::Err(__err);
                            }
                        };
                        _serde::export::Ok(ClientId(__field0))
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::export::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 =
                            match match _serde::de::SeqAccess::next_element::<ID>(&mut __seq) {
                                _serde::export::Ok(__val) => __val,
                                _serde::export::Err(__err) => {
                                    return _serde::export::Err(__err);
                                }
                            } {
                                _serde::export::Some(__value) => __value,
                                _serde::export::None => {
                                    return _serde::export::Err(_serde::de::Error::invalid_length(
                                        0usize,
                                        &"tuple struct ClientId with 1 element",
                                    ));
                                }
                            };
                        _serde::export::Ok(ClientId(__field0))
                    }
                }
                _serde::Deserializer::deserialize_newtype_struct(
                    __deserializer,
                    "ClientId",
                    __Visitor {
                        marker: _serde::export::PhantomData::<ClientId>,
                        lifetime: _serde::export::PhantomData,
                    },
                )
            }
        }
    };
    #[repr(transparent)]
    pub struct VaultId(ID);
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::marker::Copy for VaultId {}
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::clone::Clone for VaultId {
        #[inline]
        fn clone(&self) -> VaultId {
            {
                let _: ::core::clone::AssertParamIsClone<ID>;
                *self
            }
        }
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::hash::Hash for VaultId {
        fn hash<__H: ::core::hash::Hasher>(&self, state: &mut __H) -> () {
            match *self {
                VaultId(ref __self_0_0) => ::core::hash::Hash::hash(&(*__self_0_0), state),
            }
        }
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::cmp::Ord for VaultId {
        #[inline]
        fn cmp(&self, other: &VaultId) -> ::core::cmp::Ordering {
            match *other {
                VaultId(ref __self_1_0) => match *self {
                    VaultId(ref __self_0_0) => {
                        match ::core::cmp::Ord::cmp(&(*__self_0_0), &(*__self_1_0)) {
                            ::core::cmp::Ordering::Equal => ::core::cmp::Ordering::Equal,
                            cmp => cmp,
                        }
                    }
                },
            }
        }
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::cmp::PartialOrd for VaultId {
        #[inline]
        fn partial_cmp(&self, other: &VaultId) -> ::core::option::Option<::core::cmp::Ordering> {
            match *other {
                VaultId(ref __self_1_0) => match *self {
                    VaultId(ref __self_0_0) => {
                        match ::core::cmp::PartialOrd::partial_cmp(&(*__self_0_0), &(*__self_1_0)) {
                            ::core::option::Option::Some(::core::cmp::Ordering::Equal) => {
                                ::core::option::Option::Some(::core::cmp::Ordering::Equal)
                            }
                            cmp => cmp,
                        }
                    }
                },
            }
        }
        #[inline]
        fn lt(&self, other: &VaultId) -> bool {
            match *other {
                VaultId(ref __self_1_0) => match *self {
                    VaultId(ref __self_0_0) => {
                        ::core::option::Option::unwrap_or(
                            ::core::cmp::PartialOrd::partial_cmp(&(*__self_0_0), &(*__self_1_0)),
                            ::core::cmp::Ordering::Greater,
                        ) == ::core::cmp::Ordering::Less
                    }
                },
            }
        }
        #[inline]
        fn le(&self, other: &VaultId) -> bool {
            match *other {
                VaultId(ref __self_1_0) => match *self {
                    VaultId(ref __self_0_0) => {
                        ::core::option::Option::unwrap_or(
                            ::core::cmp::PartialOrd::partial_cmp(&(*__self_0_0), &(*__self_1_0)),
                            ::core::cmp::Ordering::Greater,
                        ) != ::core::cmp::Ordering::Greater
                    }
                },
            }
        }
        #[inline]
        fn gt(&self, other: &VaultId) -> bool {
            match *other {
                VaultId(ref __self_1_0) => match *self {
                    VaultId(ref __self_0_0) => {
                        ::core::option::Option::unwrap_or(
                            ::core::cmp::PartialOrd::partial_cmp(&(*__self_0_0), &(*__self_1_0)),
                            ::core::cmp::Ordering::Less,
                        ) == ::core::cmp::Ordering::Greater
                    }
                },
            }
        }
        #[inline]
        fn ge(&self, other: &VaultId) -> bool {
            match *other {
                VaultId(ref __self_1_0) => match *self {
                    VaultId(ref __self_0_0) => {
                        ::core::option::Option::unwrap_or(
                            ::core::cmp::PartialOrd::partial_cmp(&(*__self_0_0), &(*__self_1_0)),
                            ::core::cmp::Ordering::Less,
                        ) != ::core::cmp::Ordering::Less
                    }
                },
            }
        }
    }
    impl ::core::marker::StructuralEq for VaultId {}
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::cmp::Eq for VaultId {
        #[inline]
        #[doc(hidden)]
        fn assert_receiver_is_total_eq(&self) -> () {
            {
                let _: ::core::cmp::AssertParamIsEq<ID>;
            }
        }
    }
    impl ::core::marker::StructuralPartialEq for VaultId {}
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::cmp::PartialEq for VaultId {
        #[inline]
        fn eq(&self, other: &VaultId) -> bool {
            match *other {
                VaultId(ref __self_1_0) => match *self {
                    VaultId(ref __self_0_0) => (*__self_0_0) == (*__self_1_0),
                },
            }
        }
        #[inline]
        fn ne(&self, other: &VaultId) -> bool {
            match *other {
                VaultId(ref __self_1_0) => match *self {
                    VaultId(ref __self_0_0) => (*__self_0_0) != (*__self_1_0),
                },
            }
        }
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(rust_2018_idioms, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl _serde::Serialize for VaultId {
            fn serialize<__S>(
                &self,
                __serializer: __S,
            ) -> _serde::export::Result<__S::Ok, __S::Error>
            where
                __S: _serde::Serializer,
            {
                _serde::Serializer::serialize_newtype_struct(__serializer, "VaultId", &self.0)
            }
        }
    };
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(rust_2018_idioms, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl<'de> _serde::Deserialize<'de> for VaultId {
            fn deserialize<__D>(__deserializer: __D) -> _serde::export::Result<Self, __D::Error>
            where
                __D: _serde::Deserializer<'de>,
            {
                struct __Visitor<'de> {
                    marker: _serde::export::PhantomData<VaultId>,
                    lifetime: _serde::export::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = VaultId;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::export::Formatter,
                    ) -> _serde::export::fmt::Result {
                        _serde::export::Formatter::write_str(__formatter, "tuple struct VaultId")
                    }
                    #[inline]
                    fn visit_newtype_struct<__E>(
                        self,
                        __e: __E,
                    ) -> _serde::export::Result<Self::Value, __E::Error>
                    where
                        __E: _serde::Deserializer<'de>,
                    {
                        let __field0: ID = match <ID as _serde::Deserialize>::deserialize(__e) {
                            _serde::export::Ok(__val) => __val,
                            _serde::export::Err(__err) => {
                                return _serde::export::Err(__err);
                            }
                        };
                        _serde::export::Ok(VaultId(__field0))
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::export::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 =
                            match match _serde::de::SeqAccess::next_element::<ID>(&mut __seq) {
                                _serde::export::Ok(__val) => __val,
                                _serde::export::Err(__err) => {
                                    return _serde::export::Err(__err);
                                }
                            } {
                                _serde::export::Some(__value) => __value,
                                _serde::export::None => {
                                    return _serde::export::Err(_serde::de::Error::invalid_length(
                                        0usize,
                                        &"tuple struct VaultId with 1 element",
                                    ));
                                }
                            };
                        _serde::export::Ok(VaultId(__field0))
                    }
                }
                _serde::Deserializer::deserialize_newtype_struct(
                    __deserializer,
                    "VaultId",
                    __Visitor {
                        marker: _serde::export::PhantomData::<VaultId>,
                        lifetime: _serde::export::PhantomData,
                    },
                )
            }
        }
    };
    #[repr(transparent)]
    struct ID([u8; 24]);
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::marker::Copy for ID {}
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::clone::Clone for ID {
        #[inline]
        fn clone(&self) -> ID {
            {
                let _: ::core::clone::AssertParamIsClone<[u8; 24]>;
                *self
            }
        }
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::hash::Hash for ID {
        fn hash<__H: ::core::hash::Hasher>(&self, state: &mut __H) -> () {
            match *self {
                ID(ref __self_0_0) => ::core::hash::Hash::hash(&(*__self_0_0), state),
            }
        }
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::cmp::Ord for ID {
        #[inline]
        fn cmp(&self, other: &ID) -> ::core::cmp::Ordering {
            match *other {
                ID(ref __self_1_0) => match *self {
                    ID(ref __self_0_0) => {
                        match ::core::cmp::Ord::cmp(&(*__self_0_0), &(*__self_1_0)) {
                            ::core::cmp::Ordering::Equal => ::core::cmp::Ordering::Equal,
                            cmp => cmp,
                        }
                    }
                },
            }
        }
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::cmp::PartialOrd for ID {
        #[inline]
        fn partial_cmp(&self, other: &ID) -> ::core::option::Option<::core::cmp::Ordering> {
            match *other {
                ID(ref __self_1_0) => match *self {
                    ID(ref __self_0_0) => {
                        match ::core::cmp::PartialOrd::partial_cmp(&(*__self_0_0), &(*__self_1_0)) {
                            ::core::option::Option::Some(::core::cmp::Ordering::Equal) => {
                                ::core::option::Option::Some(::core::cmp::Ordering::Equal)
                            }
                            cmp => cmp,
                        }
                    }
                },
            }
        }
        #[inline]
        fn lt(&self, other: &ID) -> bool {
            match *other {
                ID(ref __self_1_0) => match *self {
                    ID(ref __self_0_0) => {
                        ::core::option::Option::unwrap_or(
                            ::core::cmp::PartialOrd::partial_cmp(&(*__self_0_0), &(*__self_1_0)),
                            ::core::cmp::Ordering::Greater,
                        ) == ::core::cmp::Ordering::Less
                    }
                },
            }
        }
        #[inline]
        fn le(&self, other: &ID) -> bool {
            match *other {
                ID(ref __self_1_0) => match *self {
                    ID(ref __self_0_0) => {
                        ::core::option::Option::unwrap_or(
                            ::core::cmp::PartialOrd::partial_cmp(&(*__self_0_0), &(*__self_1_0)),
                            ::core::cmp::Ordering::Greater,
                        ) != ::core::cmp::Ordering::Greater
                    }
                },
            }
        }
        #[inline]
        fn gt(&self, other: &ID) -> bool {
            match *other {
                ID(ref __self_1_0) => match *self {
                    ID(ref __self_0_0) => {
                        ::core::option::Option::unwrap_or(
                            ::core::cmp::PartialOrd::partial_cmp(&(*__self_0_0), &(*__self_1_0)),
                            ::core::cmp::Ordering::Less,
                        ) == ::core::cmp::Ordering::Greater
                    }
                },
            }
        }
        #[inline]
        fn ge(&self, other: &ID) -> bool {
            match *other {
                ID(ref __self_1_0) => match *self {
                    ID(ref __self_0_0) => {
                        ::core::option::Option::unwrap_or(
                            ::core::cmp::PartialOrd::partial_cmp(&(*__self_0_0), &(*__self_1_0)),
                            ::core::cmp::Ordering::Less,
                        ) != ::core::cmp::Ordering::Less
                    }
                },
            }
        }
    }
    impl ::core::marker::StructuralEq for ID {}
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::cmp::Eq for ID {
        #[inline]
        #[doc(hidden)]
        fn assert_receiver_is_total_eq(&self) -> () {
            {
                let _: ::core::cmp::AssertParamIsEq<[u8; 24]>;
            }
        }
    }
    impl ::core::marker::StructuralPartialEq for ID {}
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::cmp::PartialEq for ID {
        #[inline]
        fn eq(&self, other: &ID) -> bool {
            match *other {
                ID(ref __self_1_0) => match *self {
                    ID(ref __self_0_0) => (*__self_0_0) == (*__self_1_0),
                },
            }
        }
        #[inline]
        fn ne(&self, other: &ID) -> bool {
            match *other {
                ID(ref __self_1_0) => match *self {
                    ID(ref __self_0_0) => (*__self_0_0) != (*__self_1_0),
                },
            }
        }
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(rust_2018_idioms, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl _serde::Serialize for ID {
            fn serialize<__S>(
                &self,
                __serializer: __S,
            ) -> _serde::export::Result<__S::Ok, __S::Error>
            where
                __S: _serde::Serializer,
            {
                _serde::Serializer::serialize_newtype_struct(__serializer, "ID", &self.0)
            }
        }
    };
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(rust_2018_idioms, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl<'de> _serde::Deserialize<'de> for ID {
            fn deserialize<__D>(__deserializer: __D) -> _serde::export::Result<Self, __D::Error>
            where
                __D: _serde::Deserializer<'de>,
            {
                struct __Visitor<'de> {
                    marker: _serde::export::PhantomData<ID>,
                    lifetime: _serde::export::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = ID;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::export::Formatter,
                    ) -> _serde::export::fmt::Result {
                        _serde::export::Formatter::write_str(__formatter, "tuple struct ID")
                    }
                    #[inline]
                    fn visit_newtype_struct<__E>(
                        self,
                        __e: __E,
                    ) -> _serde::export::Result<Self::Value, __E::Error>
                    where
                        __E: _serde::Deserializer<'de>,
                    {
                        let __field0: [u8; 24] =
                            match <[u8; 24] as _serde::Deserialize>::deserialize(__e) {
                                _serde::export::Ok(__val) => __val,
                                _serde::export::Err(__err) => {
                                    return _serde::export::Err(__err);
                                }
                            };
                        _serde::export::Ok(ID(__field0))
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::export::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 =
                            match match _serde::de::SeqAccess::next_element::<[u8; 24]>(&mut __seq)
                            {
                                _serde::export::Ok(__val) => __val,
                                _serde::export::Err(__err) => {
                                    return _serde::export::Err(__err);
                                }
                            } {
                                _serde::export::Some(__value) => __value,
                                _serde::export::None => {
                                    return _serde::export::Err(_serde::de::Error::invalid_length(
                                        0usize,
                                        &"tuple struct ID with 1 element",
                                    ));
                                }
                            };
                        _serde::export::Ok(ID(__field0))
                    }
                }
                _serde::Deserializer::deserialize_newtype_struct(
                    __deserializer,
                    "ID",
                    __Visitor {
                        marker: _serde::export::PhantomData::<ID>,
                        lifetime: _serde::export::PhantomData,
                    },
                )
            }
        }
    };
    impl AsRef<[u8]> for ID {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }
    impl Debug for ID {
        fn fmt(&self, f: &mut Formatter) -> fmt::Result {
            f.write_fmt(::core::fmt::Arguments::new_v1(
                &["Chain(", ")"],
                &match (&self.0.base64(),) {
                    (arg0,) => [::core::fmt::ArgumentV1::new(
                        arg0,
                        ::core::fmt::Display::fmt,
                    )],
                },
            ))
        }
    }
    impl ID {
        pub fn random<P: BoxProvider>() -> crate::Result<Self> {
            let mut buf = [0; 24];
            P::random_buf(&mut buf)?;
            Ok(Self(buf))
        }
        pub fn load(data: &[u8]) -> crate::Result<Self> {
            data.try_into()
        }
    }
    impl VaultId {
        pub fn random<P: BoxProvider>() -> crate::Result<Self> {
            Ok(VaultId(ID::random::<P>()?))
        }
    }
    impl ClientId {
        pub fn random<P: BoxProvider>() -> crate::Result<Self> {
            Ok(ClientId(ID::random::<P>()?))
        }
    }
    impl TryFrom<&[u8]> for ID {
        type Error = crate::Error;
        fn try_from(bs: &[u8]) -> Result<Self, Self::Error> {
            if bs.len() != 24 {
                return Err(crate::Error::IDError);
            }
            let mut tmp = [0; 24];
            tmp.copy_from_slice(bs);
            Ok(Self(tmp))
        }
    }
    impl TryFrom<Vec<u8>> for ID {
        type Error = crate::Error;
        fn try_from(bs: Vec<u8>) -> Result<Self, Self::Error> {
            Self::try_from(bs.as_slice())
        }
    }
    impl TryFrom<Vec<u8>> for ClientId {
        type Error = crate::Error;
        fn try_from(bs: Vec<u8>) -> Result<Self, Self::Error> {
            Ok(ClientId(bs.try_into()?))
        }
    }
    impl TryFrom<&[u8]> for ClientId {
        type Error = crate::Error;
        fn try_from(bs: &[u8]) -> Result<Self, Self::Error> {
            Ok(ClientId(bs.try_into()?))
        }
    }
    impl Debug for ClientId {
        fn fmt(&self, f: &mut Formatter) -> fmt::Result {
            f.write_fmt(::core::fmt::Arguments::new_v1(
                &["Client(", ")"],
                &match (&self.0.as_ref().base64(),) {
                    (arg0,) => [::core::fmt::ArgumentV1::new(
                        arg0,
                        ::core::fmt::Display::fmt,
                    )],
                },
            ))
        }
    }
    impl TryFrom<Vec<u8>> for VaultId {
        type Error = crate::Error;
        fn try_from(bs: Vec<u8>) -> Result<Self, Self::Error> {
            Ok(VaultId(bs.try_into()?))
        }
    }
    impl TryFrom<&[u8]> for VaultId {
        type Error = crate::Error;
        fn try_from(bs: &[u8]) -> Result<Self, Self::Error> {
            Ok(VaultId(bs.try_into()?))
        }
    }
    impl Debug for VaultId {
        fn fmt(&self, f: &mut Formatter) -> fmt::Result {
            f.write_fmt(::core::fmt::Arguments::new_v1(
                &["Vault(", ")"],
                &match (&self.0.as_ref().base64(),) {
                    (arg0,) => [::core::fmt::ArgumentV1::new(
                        arg0,
                        ::core::fmt::Display::fmt,
                    )],
                },
            ))
        }
    }
    impl Into<Vec<u8>> for VaultId {
        fn into(self) -> Vec<u8> {
            self.0 .0.to_vec()
        }
    }
    impl AsRef<[u8]> for VaultId {
        fn as_ref(&self) -> &[u8] {
            &self.0 .0
        }
    }
}
mod key_store {
    use engine::vault::{BoxProvider, Key};
    use std::collections::HashMap;
    use crate::{ids::VaultId, line_error};
    pub struct KeyStore<P: BoxProvider + Clone + Send + Sync + 'static> {
        store: HashMap<VaultId, Key<P>>,
    }
    impl<P: BoxProvider + Clone + Send + Sync + 'static> KeyStore<P> {
        pub fn new() -> Self {
            Self {
                store: HashMap::new(),
            }
        }
        pub fn get_key(&mut self, id: VaultId) -> Option<Key<P>> {
            self.store.remove(&id)
        }
        pub fn create_key(&mut self, id: VaultId) -> Key<P> {
            let key = self
                .store
                .entry(id)
                .or_insert(Key::<P>::random().expect("Error at src\\key_store.rs:24"));
            key.clone()
        }
        pub fn insert_key(&mut self, id: VaultId, key: Key<P>) {
            self.store.entry(id).or_insert(key);
        }
        pub fn rebuild_keystore(&mut self, keys: Vec<Key<P>>) {
            let mut store: HashMap<VaultId, Key<P>> = HashMap::new();
            keys.into_iter().for_each(|key| {
                store.insert(
                    VaultId::random::<P>().expect("Error at src\\key_store.rs:37"),
                    key,
                );
            });
            self.store = store;
        }
        pub fn get_vault_ids(&mut self) -> Vec<VaultId> {
            let mut ids = Vec::new();
            self.store.keys().into_iter().for_each(|id| ids.push(*id));
            ids
        }
    }
}
mod provider {
    use engine::crypto::XChaChaPoly;
    use engine::random::{
        primitives::{cipher::AeadCipher, rng::SecureRng},
        OsRng,
    };
    use engine::vault::{BoxProvider, Error, Key, Result};
    pub struct Provider;
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::fmt::Debug for Provider {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            match *self {
                Provider => {
                    let mut debug_trait_builder = f.debug_tuple("Provider");
                    debug_trait_builder.finish()
                }
            }
        }
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::clone::Clone for Provider {
        #[inline]
        fn clone(&self) -> Provider {
            match *self {
                Provider => Provider,
            }
        }
    }
    impl Provider {
        const NONCE_LEN: usize = 24;
        const TAG_LEN: usize = 16;
    }
    impl BoxProvider for Provider {
        fn box_key_len() -> usize {
            32
        }
        fn box_overhead() -> usize {
            Self::NONCE_LEN + Self::TAG_LEN
        }
        fn box_seal(key: &Key<Self>, ad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
            let mut boxx = ::alloc::vec::from_elem(0, data.len() + Self::box_overhead());
            let (nonce, cipher) = boxx.split_at_mut(Self::NONCE_LEN);
            Self::random_buf(nonce)?;
            XChaChaPoly
                .seal_with(cipher, data, ad, key.bytes(), nonce)
                .map_err(|_| Error::CryptoError(String::from("Unable to seal data")))?;
            Ok(boxx)
        }
        fn box_open(key: &Key<Self>, ad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
            let mut plain = match data.len() {
                len if len >= Self::box_overhead() => {
                    ::alloc::vec::from_elem(0, len - Self::box_overhead())
                }
                _ => return Err(Error::CryptoError(String::from("Truncated cipher"))),
            };
            let (nonce, cipher) = data.split_at(Self::NONCE_LEN);
            XChaChaPoly
                .open_to(&mut plain, cipher, ad, key.bytes(), nonce)
                .map_err(|_| Error::CryptoError(String::from("Invalid Cipher")))?;
            Ok(plain)
        }
        fn random_buf(buf: &mut [u8]) -> Result<()> {
            OsRng
                .random(buf)
                .map_err(|_| Error::CryptoError(String::from("Can't generated random Bytes")))
        }
    }
}
mod secret {
    use serde::{de, ser, Deserialize, Serialize};
    use zeroize::Zeroize;
    pub trait ReadSecret<S>
    where
        S: Zeroize,
    {
        fn read_secret(&self) -> &S;
    }
    pub trait CloneSecret: Clone + Zeroize {}
    pub trait SerializeSecret: Serialize {}
    pub struct Secret<S>
    where
        S: Zeroize,
    {
        value: S,
    }
    impl<S> Secret<S>
    where
        S: Zeroize,
    {
        pub fn new(value: S) -> Self {
            Self { value }
        }
    }
    impl<S> ReadSecret<S> for Secret<S>
    where
        S: Zeroize,
    {
        fn read_secret(&self) -> &S {
            &self.value
        }
    }
    impl<S> From<S> for Secret<S>
    where
        S: Zeroize,
    {
        fn from(value: S) -> Self {
            Self::new(value)
        }
    }
    impl<S> Clone for Secret<S>
    where
        S: CloneSecret,
    {
        fn clone(&self) -> Self {
            Self {
                value: self.value.clone(),
            }
        }
    }
    impl<S> Drop for Secret<S>
    where
        S: Zeroize,
    {
        fn drop(&mut self) {
            self.value.zeroize()
        }
    }
    impl<'de, T> Deserialize<'de> for Secret<T>
    where
        T: Zeroize + Clone + de::DeserializeOwned + Sized,
    {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: de::Deserializer<'de>,
        {
            T::deserialize(deserializer).map(Secret::new)
        }
    }
    impl<T> Serialize for Secret<T>
    where
        T: Zeroize + SerializeSecret + Serialize + Sized,
    {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: ser::Serializer,
        {
            self.read_secret().serialize(serializer)
        }
    }
}
mod snapshot {
    use serde::{Deserialize, Serialize};
    use engine::{
        snapshot::{decrypt_snapshot, encrypt_snapshot, snapshot_dir},
        vault::BoxProvider,
    };
    use std::{fs::OpenOptions, path::PathBuf};
    pub struct Snapshot {
        pub state: Vec<u8>,
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(rust_2018_idioms, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl _serde::Serialize for Snapshot {
            fn serialize<__S>(
                &self,
                __serializer: __S,
            ) -> _serde::export::Result<__S::Ok, __S::Error>
            where
                __S: _serde::Serializer,
            {
                let mut __serde_state = match _serde::Serializer::serialize_struct(
                    __serializer,
                    "Snapshot",
                    false as usize + 1,
                ) {
                    _serde::export::Ok(__val) => __val,
                    _serde::export::Err(__err) => {
                        return _serde::export::Err(__err);
                    }
                };
                match _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "state",
                    &self.state,
                ) {
                    _serde::export::Ok(__val) => __val,
                    _serde::export::Err(__err) => {
                        return _serde::export::Err(__err);
                    }
                };
                _serde::ser::SerializeStruct::end(__serde_state)
            }
        }
    };
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(rust_2018_idioms, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl<'de> _serde::Deserialize<'de> for Snapshot {
            fn deserialize<__D>(__deserializer: __D) -> _serde::export::Result<Self, __D::Error>
            where
                __D: _serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                enum __Field {
                    __field0,
                    __ignore,
                }
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::export::Formatter,
                    ) -> _serde::export::fmt::Result {
                        _serde::export::Formatter::write_str(__formatter, "field identifier")
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::export::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::export::Ok(__Field::__field0),
                            _ => _serde::export::Err(_serde::de::Error::invalid_value(
                                _serde::de::Unexpected::Unsigned(__value),
                                &"field index 0 <= i < 1",
                            )),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::export::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "state" => _serde::export::Ok(__Field::__field0),
                            _ => _serde::export::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::export::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"state" => _serde::export::Ok(__Field::__field0),
                            _ => _serde::export::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::export::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(__deserializer, __FieldVisitor)
                    }
                }
                struct __Visitor<'de> {
                    marker: _serde::export::PhantomData<Snapshot>,
                    lifetime: _serde::export::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Snapshot;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::export::Formatter,
                    ) -> _serde::export::fmt::Result {
                        _serde::export::Formatter::write_str(__formatter, "struct Snapshot")
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::export::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match match _serde::de::SeqAccess::next_element::<Vec<u8>>(
                            &mut __seq,
                        ) {
                            _serde::export::Ok(__val) => __val,
                            _serde::export::Err(__err) => {
                                return _serde::export::Err(__err);
                            }
                        } {
                            _serde::export::Some(__value) => __value,
                            _serde::export::None => {
                                return _serde::export::Err(_serde::de::Error::invalid_length(
                                    0usize,
                                    &"struct Snapshot with 1 element",
                                ));
                            }
                        };
                        _serde::export::Ok(Snapshot { state: __field0 })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::export::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::export::Option<Vec<u8>> = _serde::export::None;
                        while let _serde::export::Some(__key) =
                            match _serde::de::MapAccess::next_key::<__Field>(&mut __map) {
                                _serde::export::Ok(__val) => __val,
                                _serde::export::Err(__err) => {
                                    return _serde::export::Err(__err);
                                }
                            }
                        {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::export::Option::is_some(&__field0) {
                                        return _serde::export::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "state",
                                            ),
                                        );
                                    }
                                    __field0 = _serde::export::Some(
                                        match _serde::de::MapAccess::next_value::<Vec<u8>>(
                                            &mut __map,
                                        ) {
                                            _serde::export::Ok(__val) => __val,
                                            _serde::export::Err(__err) => {
                                                return _serde::export::Err(__err);
                                            }
                                        },
                                    );
                                }
                                _ => {
                                    let _ = match _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map)
                                    {
                                        _serde::export::Ok(__val) => __val,
                                        _serde::export::Err(__err) => {
                                            return _serde::export::Err(__err);
                                        }
                                    };
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::export::Some(__field0) => __field0,
                            _serde::export::None => {
                                match _serde::private::de::missing_field("state") {
                                    _serde::export::Ok(__val) => __val,
                                    _serde::export::Err(__err) => {
                                        return _serde::export::Err(__err);
                                    }
                                }
                            }
                        };
                        _serde::export::Ok(Snapshot { state: __field0 })
                    }
                }
                const FIELDS: &'static [&'static str] = &["state"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "Snapshot",
                    FIELDS,
                    __Visitor {
                        marker: _serde::export::PhantomData::<Snapshot>,
                        lifetime: _serde::export::PhantomData,
                    },
                )
            }
        }
    };
    impl Snapshot {
        pub fn new<P>(state: Vec<u8>) -> Self {
            Self { state }
        }
        pub fn get_state(self) -> Vec<u8> {
            self.state
        }
        pub fn get_snapshot_path() -> PathBuf {
            let path = snapshot_dir().expect("Unable to get the snapshot directory");
            path.join("backup.snapshot")
        }
        pub fn read_from_snapshot<P>(snapshot: &PathBuf, pass: &str) -> Self
        where
            P: BoxProvider + Clone + Send + Sync,
        {
            let mut buffer = Vec::new();
            let mut file = OpenOptions :: new () . read (true) . open (snapshot) . expect ("Unable to access snapshot. Make sure that it exists or run encrypt to build a new one.") ;
            decrypt_snapshot(&mut file, &mut buffer, pass.as_bytes())
                .expect("unable to decrypt the snapshot");
            Snapshot::new::<P>(buffer)
        }
        pub fn write_to_snapshot(self, snapshot: &PathBuf, pass: &str) {
            let mut file = OpenOptions :: new () . write (true) . create (true) . open (snapshot) . expect ("Unable to access snapshot. Make sure that it exists or run encrypt to build a new one.") ;
            file.set_len(0)
                .expect("unable to clear the contents of the file file");
            encrypt_snapshot(self.state, &mut file, pass.as_bytes())
                .expect("Couldn't write to the snapshot");
        }
    }
}
pub use crate::ids::{ClientId, VaultId};
pub type Result<T> = anyhow::Result<T, Error>;
pub enum Error {
    #[error("Id Error")]
    IDError,
    #[error("Vault Error: {0}")]
    VaultError(#[from] engine::vault::Error),
}
#[allow(unused_qualifications)]
impl std::error::Error for Error {
    fn source(&self) -> std::option::Option<&(dyn std::error::Error + 'static)> {
        use thiserror::private::AsDynError;
        #[allow(deprecated)]
        match self {
            Error::IDError { .. } => std::option::Option::None,
            Error::VaultError { 0: source, .. } => std::option::Option::Some(source.as_dyn_error()),
        }
    }
}
#[allow(unused_qualifications)]
impl std::fmt::Display for Error {
    fn fmt(&self, __formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        #[allow(unused_imports)]
        use thiserror::private::{DisplayAsDisplay, PathAsDisplay};
        #[allow(unused_variables, deprecated, clippy::used_underscore_binding)]
        match self {
            Error::IDError {} => __formatter.write_fmt(::core::fmt::Arguments::new_v1(
                &["Id Error"],
                &match () {
                    () => [],
                },
            )),
            Error::VaultError(_0) => __formatter.write_fmt(::core::fmt::Arguments::new_v1(
                &["Vault Error: "],
                &match (&_0.as_display(),) {
                    (arg0,) => [::core::fmt::ArgumentV1::new(
                        arg0,
                        ::core::fmt::Display::fmt,
                    )],
                },
            )),
        }
    }
}
#[allow(unused_qualifications)]
impl std::convert::From<engine::vault::Error> for Error {
    #[allow(deprecated)]
    fn from(source: engine::vault::Error) -> Self {
        Error::VaultError { 0: source }
    }
}
#[automatically_derived]
#[allow(unused_qualifications)]
impl ::core::fmt::Debug for Error {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        match (&*self,) {
            (&Error::IDError,) => {
                let mut debug_trait_builder = f.debug_tuple("IDError");
                debug_trait_builder.finish()
            }
            (&Error::VaultError(ref __self_0),) => {
                let mut debug_trait_builder = f.debug_tuple("VaultError");
                let _ = debug_trait_builder.field(&&(*__self_0));
                debug_trait_builder.finish()
            }
        }
    }
}
