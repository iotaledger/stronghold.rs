// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// use riker::actors::*;

// use std::{fmt::Debug, path::PathBuf};

// use engine::vault::{BoxProvider, RecordHint, RecordId};

// use runtime::zone::soft;

// use crate::{
//     bucket::Bucket,
//     client::{ClientMsg, InternalResults},
//     ids::VaultId,
//     key_store::KeyStore,
//     line_error,
//     provider::Provider,
//     snapshot::Snapshot,
// };

// pub struct InternalActor<P: BoxProvider + Send + Sync + Clone + 'static> {
//     bucket: Bucket<P>,
//     keystore: KeyStore<P>,
// }

// /// Messages used for the KeyStore Actor.
// #[derive(Clone, Debug)]
// pub enum InternalMsg {
//     StoreKeyData(VaultId, RecordId, Vec<u8>),
//     CreateVault(VaultId),
//     ReadData(VaultId, RecordId),
//     WriteData(VaultId, RecordId, Vec<u8>, RecordHint),
//     InitRecord(VaultId),
//     RevokeData(VaultId, RecordId),
//     GarbageCollect(VaultId),
//     ListIds(VaultId),
//     WriteSnapshot(String, Option<String>, Option<PathBuf>),
//     ReadSnapshot(String, Option<String>, Option<PathBuf>),
//     ReloadData(Vec<u8>),
//     ClearCache,
// }

// /// Messages used for the Snapshot Actor.
// #[derive(Clone, Debug)]
// pub enum SMsg {
//     WriteSnapshot(String, Option<String>, Option<PathBuf>, Vec<u8>),
//     ReadSnapshot(String, Option<String>, Option<PathBuf>),
// }

// impl ActorFactory for InternalActor<Provider> {
//     fn create() -> Self {
//         let bucket = Bucket::new();
//         let keystore = KeyStore::new();

//         Self { bucket, keystore }
//     }
// }

// impl Actor for InternalActor<Provider> {
//     type Msg = InternalMsg;

//     fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
//         self.receive(ctx, msg, sender);
//     }
// }

// impl Receive<InternalMsg> for InternalActor<Provider> {
//     type Msg = InternalMsg;

//     fn receive(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, _sender: Sender) {
//         soft(|| match msg {
//             InternalMsg::CreateVault(vid) => {
//                 let key = self.keystore.create_key(vid);

//                 let (_, rid) = self.bucket.create_and_init_vault(key);

//                 let client = ctx.select("/user/stronghold-internal/").expect(line_error!());
//                 client.try_tell(
//                     ClientMsg::InternalResults(InternalResults::ReturnCreateVault(vid, rid)),
//                     None,
//                 );
//             }
//             InternalMsg::ReadData(vid, rid) => {
//                 if let Some(key) = self.keystore.get_key(vid) {
//                     let plain = self.bucket.read_data(key.clone(), rid);

//                     self.keystore.insert_key(vid, key);

//                     let client = ctx.select("/user/stronghold-internal/").expect(line_error!());
//                     client.try_tell(ClientMsg::InternalResults(InternalResults::ReturnReadData(plain)), None);
//                 }
//             }
//             InternalMsg::WriteData(vid, rid, payload, hint) => {
//                 if let Some(key) = self.keystore.get_key(vid) {
//                     self.bucket.write_payload(key.clone(), rid, payload, hint);

//                     self.keystore.insert_key(vid, key);
//                 }
//             }
//             InternalMsg::InitRecord(vid) => {
//                 if let Some(key) = self.keystore.get_key(vid) {
//                     let rid = self.bucket.init_record(key.clone());

//                     self.keystore.insert_key(vid, key);

//                     let client = ctx.select("/user/stronghold-internal/").expect(line_error!());
//                     client.try_tell(
//                         ClientMsg::InternalResults(InternalResults::ReturnInitRecord(vid, rid)),
//                         None,
//                     );
//                 }
//             }
//             InternalMsg::RevokeData(vid, rid) => {
//                 if let Some(key) = self.keystore.get_key(vid) {
//                     self.bucket.revoke_data(key.clone(), rid);

//                     self.keystore.insert_key(vid, key);
//                 }
//             }
//             InternalMsg::GarbageCollect(vid) => {
//                 if let Some(key) = self.keystore.get_key(vid) {
//                     self.bucket.garbage_collect(key.clone());

//                     self.keystore.insert_key(vid, key);
//                 }
//             }
//             InternalMsg::ListIds(vid) => {
//                 if let Some(key) = self.keystore.get_key(vid) {
//                     let ids = self.bucket.list_ids(key.clone());

//                     self.keystore.insert_key(vid, key);

//                     let client = ctx.select("/user/stronghold-internal/").expect(line_error!());
//                     client.try_tell(ClientMsg::InternalResults(InternalResults::ReturnList(ids)), None);
//                 }
//             }
//             InternalMsg::ReloadData(data) => {
//                 let (keys, rids) = self.bucket.repopulate_data(data);

//                 let vids = self.keystore.rebuild_keystore(keys);

//                 let client = ctx.select("/user/stronghold-internal/").expect(line_error!());
//                 client.try_tell(
//                     ClientMsg::InternalResults(InternalResults::RebuildCache(vids, rids)),
//                     None,
//                 );
//             }
//             InternalMsg::WriteSnapshot(pass, name, path) => {
//                 let state = self.bucket.offload_data();

//                 let snapshot = ctx.select("/user/snapshot/").expect(line_error!());
//                 snapshot.try_tell(SMsg::WriteSnapshot(pass, name, path, state), None);
//             }
//             InternalMsg::ReadSnapshot(pass, name, path) => {
//                 let snapshot = ctx.select("/user/snapshot/").expect(line_error!());
//                 snapshot.try_tell(SMsg::ReadSnapshot(pass, name, path), None);
//             }
//             InternalMsg::ClearCache => {
//                 self.bucket.clear_cache();
//                 self.keystore.clear_keys();
//             }
//             InternalMsg::StoreKeyData(vid, rid, data) => {}
//         })
//         .expect(line_error!());
//     }
// }

// /// Actor Factory for the Snapshot.
// impl ActorFactory for Snapshot {
//     fn create() -> Self {
//         Snapshot::new::<Provider>(vec![])
//     }
// }

// impl Actor for Snapshot {
//     type Msg = SMsg;

//     fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
//         self.receive(ctx, msg, sender);
//     }
// }

// impl Receive<SMsg> for Snapshot {
//     type Msg = SMsg;

//     fn receive(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, _sender: Sender) {
//         match msg {
//             SMsg::WriteSnapshot(pass, name, path, state) => {
//                 let snapshot = Snapshot::new::<Provider>(state);

//                 let path = if let Some(p) = path {
//                     p
//                 } else {
//                     Snapshot::get_snapshot_path(name)
//                 };

//                 snapshot.write_to_snapshot(&path, &pass);
//             }
//             SMsg::ReadSnapshot(pass, name, path) => {
//                 let path = if let Some(p) = path {
//                     p
//                 } else {
//                     Snapshot::get_snapshot_path(name)
//                 };

//                 let snapshot = Snapshot::read_from_snapshot::<Provider>(&path, &pass);

//                 let bucket = ctx.select("/user/internal-actor/").expect(line_error!());
//                 bucket.try_tell(InternalMsg::ReloadData(snapshot.get_state()), None);
//             }
//         }
//     }
// }
