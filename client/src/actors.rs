// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use riker::actors::*;

use std::{fmt::Debug, path::PathBuf};

use engine::vault::{BoxProvider, Key, RecordHint, RecordId};

use crate::{
    bucket::Bucket,
    client::{ClientMsg, InternalResults},
    ids::VaultId,
    key_store::KeyStore,
    line_error,
    provider::Provider,
    snapshot::Snapshot,
};

/// Messages used to talk to the Bucket Actor.
#[derive(Debug, Clone)]
pub enum BMsg<P: BoxProvider + Debug> {
    CreateVault(VaultId, Key<P>),
    ReadData(Key<P>, RecordId),
    WriteData(Key<P>, RecordId, Vec<u8>, RecordHint),
    InitRecord(Key<P>, VaultId),
    RevokeData(Key<P>, RecordId),
    GarbageCollect(Key<P>),
    ListAsk(Key<P>),
    WriteSnapshot(String, Option<String>, Option<PathBuf>),
    ReadSnapshot(String, Option<String>, Option<PathBuf>),
    ReloadData(Vec<u8>),
}

/// Messages used for the KeyStore Actor.
#[derive(Clone, Debug)]
pub enum KMsg {
    CreateVault(VaultId),
    ReadData(VaultId, RecordId),
    WriteData(VaultId, RecordId, Vec<u8>, RecordHint),
    InitRecord(VaultId),
    RevokeData(VaultId, RecordId),
    GarbageCollect(VaultId),
    ListIds(VaultId),
    RebuildKeys(Vec<Key<Provider>>, Vec<Vec<RecordId>>),
}

/// Messages used for the Snapshot Actor.
#[derive(Clone, Debug)]
pub enum SMsg {
    WriteSnapshot(String, Option<String>, Option<PathBuf>, Vec<u8>),
    ReadSnapshot(String, Option<String>, Option<PathBuf>),
}

/// Actor Factory for the Bucket.
impl ActorFactory for Bucket<Provider> {
    fn create() -> Self {
        Bucket::new()
    }
}

/// Actor Factory for the KeyStore.
impl ActorFactory for KeyStore<Provider> {
    fn create() -> Self {
        KeyStore::new()
    }
}

/// Actor Factory for the Snapshot.
impl ActorFactory for Snapshot {
    fn create() -> Self {
        Snapshot::new::<Provider>(vec![])
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
            SMsg::WriteSnapshot(pass, name, path, state) => {
                let snapshot = Snapshot::new::<Provider>(state);

                let path = if let Some(p) = path {
                    p
                } else {
                    Snapshot::get_snapshot_path(name)
                };

                snapshot.write_to_snapshot(&path, &pass);
            }
            SMsg::ReadSnapshot(pass, name, path) => {
                let path = if let Some(p) = path {
                    p
                } else {
                    Snapshot::get_snapshot_path(name)
                };

                let snapshot = Snapshot::read_from_snapshot::<Provider>(&path, &pass);

                let bucket = ctx.select("/user/bucket/").expect(line_error!());
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

                let client = ctx.select("/user/client/").expect(line_error!());
                client.try_tell(
                    ClientMsg::InternalResults(InternalResults::ReturnCreateVault(vid, rid)),
                    None,
                );
            }
            BMsg::ReadData(key, rid) => {
                let plain = self.read_data(key, rid);

                let client = ctx.select("/user/client/").expect(line_error!());
                client.try_tell(ClientMsg::InternalResults(InternalResults::ReturnReadData(plain)), None);
            }
            BMsg::WriteData(key, rid, payload, hint) => {
                self.write_payload(key, rid, payload, hint);
            }
            BMsg::InitRecord(key, vid) => {
                let rid = self.init_record(key);

                let client = ctx.select("/user/client/").expect(line_error!());
                client.try_tell(
                    ClientMsg::InternalResults(InternalResults::ReturnInitRecord(vid, rid)),
                    None,
                );
            }
            BMsg::RevokeData(key, rid) => {
                self.revoke_data(key, rid);
            }
            BMsg::GarbageCollect(key) => {
                self.garbage_collect(key);
            }
            BMsg::ListAsk(key) => {
                let ids = self.list_ids(key);

                let client = ctx.select("/user/client/").expect(line_error!());
                client.try_tell(ClientMsg::InternalResults(InternalResults::ReturnList(ids)), None);
            }
            BMsg::WriteSnapshot(pass, name, path) => {
                let state = self.offload_data();

                let snapshot = ctx.select("/user/snapshot/").expect(line_error!());
                snapshot.try_tell(SMsg::WriteSnapshot(pass, name, path, state), None);
            }
            BMsg::ReadSnapshot(pass, name, path) => {
                let snapshot = ctx.select("/user/snapshot/").expect(line_error!());
                snapshot.try_tell(SMsg::ReadSnapshot(pass, name, path), None);
            }
            BMsg::ReloadData(state) => {
                let (keys, rids) = self.repopulate_data(state);

                let keystore = ctx.select("/user/keystore/").expect(line_error!());
                keystore.try_tell(KMsg::RebuildKeys(keys, rids), None);
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

                let bucket = ctx.select("/user/bucket/").expect(line_error!());
                bucket.try_tell(BMsg::CreateVault(vid, key), None);
            }
            KMsg::ReadData(vid, rid) => {
                if let Some(key) = self.get_key(vid) {
                    let bucket = ctx.select("/user/bucket/").expect(line_error!());
                    bucket.try_tell(BMsg::ReadData(key.clone(), rid), None);

                    self.insert_key(vid, key);
                }
            }
            KMsg::WriteData(vid, rid, payload, hint) => {
                if let Some(key) = self.get_key(vid) {
                    let bucket = ctx.select("/user/bucket/").expect(line_error!());
                    bucket.try_tell(BMsg::WriteData(key.clone(), rid, payload, hint), None);

                    self.insert_key(vid, key);
                }
            }
            KMsg::InitRecord(vid) => {
                if let Some(key) = self.get_key(vid) {
                    let bucket = ctx.select("/user/bucket/").expect(line_error!());
                    bucket.try_tell(BMsg::InitRecord(key.clone(), vid), None);

                    self.insert_key(vid, key);
                }
            }
            KMsg::RevokeData(vid, rid) => {
                if let Some(key) = self.get_key(vid) {
                    let bucket = ctx.select("/user/bucket/").expect(line_error!());
                    bucket.try_tell(BMsg::RevokeData(key.clone(), rid), None);

                    self.insert_key(vid, key);
                }
            }
            KMsg::GarbageCollect(vid) => {
                if let Some(key) = self.get_key(vid) {
                    let bucket = ctx.select("/user/bucket/").expect(line_error!());
                    bucket.try_tell(BMsg::GarbageCollect(key.clone()), None);

                    self.insert_key(vid, key);
                }
            }
            KMsg::ListIds(vid) => {
                if let Some(key) = self.get_key(vid) {
                    let bucket = ctx.select("/user/bucket/").expect(line_error!());
                    bucket.try_tell(BMsg::ListAsk(key.clone()), None);

                    self.insert_key(vid, key);
                }
            }

            KMsg::RebuildKeys(keys, rids) => {
                let vids = self.rebuild_keystore(keys);

                let client = ctx.select("/user/client/").expect(line_error!());
                client.try_tell(
                    ClientMsg::InternalResults(InternalResults::RebuildCache(vids, rids)),
                    None,
                );
            }
        }
    }
}
