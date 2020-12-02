// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use riker::actors::*;

use std::{fmt::Debug, path::PathBuf};

use engine::vault::{BoxProvider, RecordHint, RecordId};

use runtime::zone::soft;

use crate::{
    bucket::Bucket,
    client::{ClientMsg, InternalResults},
    ids::VaultId,
    key_store::KeyStore,
    line_error,
    provider::Provider,
    snapshot::Snapshot,
};

pub struct InternalActor<P: BoxProvider + Send + Sync + Clone + 'static> {
    bucket: Bucket<P>,
    keystore: KeyStore<P>,
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
    WriteSnapshot(String, Option<String>, Option<PathBuf>),
    ReadSnapshot(String, Option<String>, Option<PathBuf>),
    ReloadData(Vec<u8>),
    ClearCache,
}

/// Messages used for the Snapshot Actor.
#[derive(Clone, Debug)]
pub enum SMsg {
    WriteSnapshot(String, Option<String>, Option<PathBuf>, Vec<u8>),
    ReadSnapshot(String, Option<String>, Option<PathBuf>),
}

impl ActorFactory for InternalActor<Provider> {
    fn create() -> Self {
        let bucket = Bucket::new();
        let keystore = KeyStore::new();

        Self { bucket, keystore }
    }
}

impl Actor for InternalActor<Provider> {
    type Msg = KMsg;

    fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        self.receive(ctx, msg, sender);
    }
}

impl Receive<KMsg> for InternalActor<Provider> {
    type Msg = KMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, _sender: Sender) {
        soft(|| match msg {
            KMsg::CreateVault(vid) => {
                let key = self.keystore.create_key(vid);

                let (_, rid) = self.bucket.create_and_init_vault(key);

                let client = ctx.select("/user/stronghold-internal/").expect(line_error!());
                client.try_tell(
                    ClientMsg::InternalResults(InternalResults::ReturnCreateVault(vid, rid)),
                    None,
                );
            }
            KMsg::ReadData(vid, rid) => {
                if let Some(key) = self.keystore.get_key(vid) {
                    let plain = self.bucket.read_data(key.clone(), rid);

                    self.keystore.insert_key(vid, key);

                    let client = ctx.select("/user/stronghold-internal/").expect(line_error!());
                    client.try_tell(ClientMsg::InternalResults(InternalResults::ReturnReadData(plain)), None);
                }
            }
            KMsg::WriteData(vid, rid, payload, hint) => {
                if let Some(key) = self.keystore.get_key(vid) {
                    self.bucket.write_payload(key.clone(), rid, payload, hint);

                    self.keystore.insert_key(vid, key);
                }
            }
            KMsg::InitRecord(vid) => {
                if let Some(key) = self.keystore.get_key(vid) {
                    let rid = self.bucket.init_record(key.clone());

                    self.keystore.insert_key(vid, key);

                    let client = ctx.select("/user/stronghold-internal/").expect(line_error!());
                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnInitRecord(vid, rid)),
                        None,
                    );
                }
            }
            KMsg::RevokeData(vid, rid) => {
                if let Some(key) = self.keystore.get_key(vid) {
                    self.bucket.revoke_data(key.clone(), rid);

                    self.keystore.insert_key(vid, key);
                }
            }
            KMsg::GarbageCollect(vid) => {
                if let Some(key) = self.keystore.get_key(vid) {
                    self.bucket.garbage_collect(key.clone());

                    self.keystore.insert_key(vid, key);
                }
            }
            KMsg::ListIds(vid) => {
                if let Some(key) = self.keystore.get_key(vid) {
                    let ids = self.bucket.list_ids(key.clone());

                    self.keystore.insert_key(vid, key);

                    let client = ctx.select("/user/stronghold-internal/").expect(line_error!());
                    client.try_tell(ClientMsg::InternalResults(InternalResults::ReturnList(ids)), None);
                }
            }
            KMsg::ReloadData(data) => {
                let (keys, rids) = self.bucket.repopulate_data(data);

                let vids = self.keystore.rebuild_keystore(keys);

                let client = ctx.select("/user/stronghold-internal/").expect(line_error!());
                client.try_tell(
                    ClientMsg::InternalResults(InternalResults::RebuildCache(vids, rids)),
                    None,
                );
            }
            KMsg::WriteSnapshot(pass, name, path) => {
                let state = self.bucket.offload_data();

                let snapshot = ctx.select("/user/snapshot/").expect(line_error!());
                snapshot.try_tell(SMsg::WriteSnapshot(pass, name, path, state), None);
            }
            KMsg::ReadSnapshot(pass, name, path) => {
                let snapshot = ctx.select("/user/snapshot/").expect(line_error!());
                snapshot.try_tell(SMsg::ReadSnapshot(pass, name, path), None);
            }
            KMsg::ClearCache => {
                self.bucket.clear_cache();
                self.keystore.clear_keys();
            }
        })
        .expect(line_error!());
    }
}

/// Actor Factory for the Snapshot.
impl ActorFactory for Snapshot {
    fn create() -> Self {
        Snapshot::new::<Provider>(vec![])
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

                let bucket = ctx.select("/user/internal-actor/").expect(line_error!());
                bucket.try_tell(KMsg::ReloadData(snapshot.get_state()), None);
            }
        }
    }
}
