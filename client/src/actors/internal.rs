// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use riker::actors::*;

use std::{fmt::Debug, path::PathBuf};

use engine::vault::{BoxProvider, RecordHint, RecordId};

use runtime::zone::soft;

use crate::{
    actors::{ProcResult, SMsg},
    bucket::Bucket,
    client::ClientMsg,
    internals::Provider,
    key_store::KeyStore,
    line_error,
    utils::{StatusMessage, VaultId},
};

pub struct InternalActor<P: BoxProvider + Send + Sync + Clone + 'static> {
    bucket: Bucket<P>,
    keystore: KeyStore<P>,
}

/// Messages used for the KeyStore Actor.
#[derive(Clone, Debug)]
pub enum InternalMsg {
    StoreKeyData(VaultId, RecordId, Vec<u8>),
    CreateVault(VaultId, RecordId),
    ReadData(VaultId, RecordId),
    WriteData(VaultId, RecordId, Vec<u8>, RecordHint),
    InitRecord(VaultId),
    RevokeData(VaultId, RecordId),
    GarbageCollect(VaultId),
    ListIds(VaultId),
    WriteSnapshot(Vec<u8>, Option<String>, Option<PathBuf>),
    ReadSnapshot(Vec<u8>, Option<String>, Option<PathBuf>),
    ReloadData(Vec<u8>),
    ClearCache,
}

/// Messages used internally by the client.
#[derive(Clone, Debug)]
pub enum InternalResults {
    ReturnCreateVault(VaultId, RecordId, StatusMessage),
    ReturnWriteData(StatusMessage),
    ReturnInitRecord(VaultId, RecordId, StatusMessage),
    ReturnReadData(Vec<u8>, StatusMessage),
    ReturnRevoke(StatusMessage),
    ReturnGarbage(StatusMessage),
    ReturnList(Vec<(Vec<u8>, RecordHint)>, StatusMessage),
    ReturnWriteSnap(StatusMessage),
    ReturnReadSnap(StatusMessage),
    ReturnControlRequest(ProcResult),
    RebuildCache(Vec<Vec<u8>>, Vec<Vec<Vec<u8>>>, StatusMessage),
}

impl ActorFactory for InternalActor<Provider> {
    fn create() -> Self {
        let bucket = Bucket::new();
        let keystore = KeyStore::new();

        Self { bucket, keystore }
    }
}

impl Actor for InternalActor<Provider> {
    type Msg = InternalMsg;

    fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        self.receive(ctx, msg, sender);
    }
}

impl Receive<InternalMsg> for InternalActor<Provider> {
    type Msg = InternalMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, _sender: Sender) {
        soft(|| match msg {
            InternalMsg::CreateVault(vid, rid) => {
                let key = self.keystore.create_key(vid);

                let (_, rid) = self.bucket.create_and_init_vault(key, rid);

                let client = ctx.select("/user/stronghold-internal/").expect(line_error!());
                client.try_tell(
                    ClientMsg::InternalResults(InternalResults::ReturnCreateVault(vid, rid, StatusMessage::Ok)),
                    None,
                );
            }
            InternalMsg::ReadData(vid, rid) => {
                let client = ctx.select("/user/stronghold-internal/").expect(line_error!());
                if let Some(key) = self.keystore.get_key(vid) {
                    let plain = self.bucket.read_data(key.clone(), rid);

                    self.keystore.insert_key(vid, key);

                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnReadData(plain, StatusMessage::Ok)),
                        None,
                    );
                } else {
                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnReadData(
                            vec![],
                            StatusMessage::Error("Vault does not exist.".into()),
                        )),
                        None,
                    );
                }
            }
            InternalMsg::WriteData(vid, rid, payload, hint) => {
                let client = ctx.select("/user/stronghold-internal/").expect(line_error!());

                if let Some(key) = self.keystore.get_key(vid) {
                    self.bucket.write_payload(key.clone(), rid, payload, hint);

                    self.keystore.insert_key(vid, key);

                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnWriteData(StatusMessage::Ok)),
                        None,
                    );
                } else {
                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnWriteData(StatusMessage::Error(
                            "Vault doesn't exist".into(),
                        ))),
                        None,
                    );
                }
            }
            InternalMsg::InitRecord(vid) => {
                if let Some(key) = self.keystore.get_key(vid) {
                    // let rid = self.bucket.init_record(key.clone());

                    self.keystore.insert_key(vid, key);

                    let client = ctx.select("/user/stronghold-internal/").expect(line_error!());
                    // client.try_tell(
                    //     ClientMsg::InternalResults(InternalResults::ReturnInitRecord(vid, rid)),
                    //     None,
                    // );
                }
            }
            InternalMsg::RevokeData(vid, rid) => {
                if let Some(key) = self.keystore.get_key(vid) {
                    self.bucket.revoke_data(key.clone(), rid);

                    self.keystore.insert_key(vid, key);
                }
            }
            InternalMsg::GarbageCollect(vid) => {
                if let Some(key) = self.keystore.get_key(vid) {
                    self.bucket.garbage_collect(key.clone());

                    self.keystore.insert_key(vid, key);
                }
            }
            InternalMsg::ListIds(vid) => {
                if let Some(key) = self.keystore.get_key(vid) {
                    let ids = self.bucket.list_ids(key.clone());

                    self.keystore.insert_key(vid, key);

                    let client = ctx.select("/user/stronghold-internal/").expect(line_error!());
                    // client.try_tell(ClientMsg::InternalResults(InternalResults::ReturnList(ids)), None);
                }
            }
            InternalMsg::ReloadData(data) => {
                let (keys, rids) = self.bucket.repopulate_data(data);

                let vids = self.keystore.rebuild_keystore(keys);

                let client = ctx.select("/user/stronghold-internal/").expect(line_error!());
                // client.try_tell(
                //     ClientMsg::InternalResults(InternalResults::RebuildCache(vids, rids)),
                //     None,
                // );
            }
            InternalMsg::WriteSnapshot(pass, name, path) => {
                let state = self.bucket.offload_data();

                let snapshot = ctx.select("/user/snapshot/").expect(line_error!());
                snapshot.try_tell(SMsg::WriteSnapshot(pass, name, path, state), None);
            }
            InternalMsg::ReadSnapshot(pass, name, path) => {
                let snapshot = ctx.select("/user/snapshot/").expect(line_error!());
                snapshot.try_tell(SMsg::ReadSnapshot(pass, name, path), None);
            }
            InternalMsg::ClearCache => {
                self.bucket.clear_cache();
                self.keystore.clear_keys();
            }
            InternalMsg::StoreKeyData(vid, rid, data) => {}
        })
        .expect(line_error!());
    }
}
