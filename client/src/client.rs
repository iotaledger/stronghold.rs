// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    ids::{ClientId, VaultId},
    line_error,
    provider::Provider,
    runtime::RMsg,
};
use std::path::PathBuf;

use engine::vault::{RecordHint, RecordId};

use riker::actors::*;

use std::collections::HashMap;

/// A `Client` Cache Actor which routes external messages to the rest of the Stronghold system.
pub struct Client {
    id: ClientId,
    key_data: Option<Vec<u8>>,
    // Contains the vault ids and the record ids with their associated indexes.
    vaults: HashMap<VaultId, (usize, Vec<RecordId>)>,
    // Contains the Record Ids for the most recent Record in each vault.
    heads: Vec<RecordId>,
}

// #[derive(Debug, Clone)]
// pub enum Procedure {
//     SIP10 {
//         seed: Vec<u8>,
//         vault_path: Vec<u8>,
//         record_path: Vec<u8>,
//         hint: RecordHint,
//     },
// }

// #[derive(Clone, Debug)]
// pub enum SHRequest {
//     // Creates a new Vault.
//     CreateNewVault(Vec<u8>),
//     // Writes data to a record in the vault.  Accepts the vault `Vec<u8>` path, an optional record `Vec<u8>` path,
// the payload and the record     // hint.  If a record path is not specified, the write will default to the head of the
// vault.  Returns     // `ReturnCreate`.
//     WriteData(Vec<u8>, Option<Vec<u8>>, Vec<u8>, RecordHint),
//     // Moves the head forward in the specified Vault and opens a new record.  Returns `ReturnInit`.
//     InitRecord(Vec<u8>),
//     // Reads data from a record in the vault. Accepts a vault `Vec<u8>` path and an optional record `Vec<u8>` path.
// If the record path is not     // specified, it reads the head.  Returns with `ReturnRead`.
//     ReadData(Vec<u8>, Option<Vec<u8>>),
//     // Marks a Record for deletion.  Accepts a vault `Vec<u8>` path and a record `Vec<u8>` path.  Deletion only
// occurs after a     // `GarbageCollect` is called.
//     RevokeData(Vec<u8>, Vec<u8>),
//     // Garbages collects any marked records on a Vault. Accepts the Vec<u8> path for the vault.
//     GarbageCollect(Vec<u8>),
//     // Lists all of the record ids and the record hints for the records in a vault.  Accepts a `Vec<u8>` path and
// returns     // with `ReturnList`.
//     ListIds(Vec<u8>),
//     // Writes to the snapshot file.  Accepts the password, an optional filename and an optional filepath.  Defaults
// to     // `$HOME/.engine/snapshots/backup.snapshot`.
//     WriteSnapshot(String, Option<String>, Option<PathBuf>),
//     // Reads from the snapshot file.  Accepts the password, an optional filename and an optional filepath.  Defaults
//     // to `$HOME/.engine/snapshots/backup.snapshot`.
//     ReadSnapshot(String, Option<String>, Option<PathBuf>),
//     ClearCache,
//     // Requests to preform a procedure in the runtime.  Takes a Procedure and its associated arguments.
//     ControlRequest(Procedure),
// }

// /// Messages that come from stronghold
// #[derive(Clone, Debug)]
// pub enum SHResults {
//     // Results from calling `CreateNewVault`.
//     ReturnCreate(Vec<u8>, Vec<u8>),
//     // Results from calling `InitRecord`.
//     ReturnInit(Vec<u8>, Vec<u8>),
//     // Results from calling `ReadData`
//     ReturnRead(Vec<u8>),
//     // Results from calling `ListIds`
//     ReturnList(Vec<(Vec<u8>, Vec<u8>)>),
//     // Results from calling `ReadSnapshot`
//     ReturnRebuild(Vec<Vec<u8>>, Vec<Vec<Vec<u8>>>),
// }

// /// Messages used internally by the client.
// #[derive(Clone, Debug)]
// pub enum InternalResults {
//     ReturnCreateVault(Vec<u8>, Vec<u8>),
//     ReturnInitRecord(Vec<u8>, Vec<u8>),
//     ReturnReadData(Vec<u8>),
//     ReturnList(Vec<(Vec<u8>, RecordHint)>),
//     RebuildCache(Vec<Vec<u8>>, Vec<Vec<Vec<u8>>>),
// }

impl Client {
    /// Creates a new Client given a `ClientID` and `ChannelRef<SHResults>`
    pub fn new(data: Vec<u8>, path: Vec<u8>) -> Self {
        let vaults = HashMap::new();
        let heads = Vec::new();
        let id = ClientId::load_from_path(&data, &path).expect(line_error!());

        Self {
            id,
            key_data: Some(data),
            vaults,
            heads,
        }
    }

    /// Add a vault to the client.  Returns a Tuple of `VaultId` and `RecordId`.
    pub fn add_vault(&mut self, vid: VaultId, rid: RecordId) -> (VaultId, RecordId) {
        self.heads.push(rid);

        let idx = self.heads.len();

        let idx = idx - 1;

        self.vaults.insert(vid, (idx, vec![rid]));

        (vid, rid)
    }

    /// Insert a new Record into the Stronghold on the Vault based on the given RecordId.
    pub fn insert_record(&mut self, vid: VaultId, rid: RecordId) -> RecordId {
        let mut heads: Vec<RecordId> = self.heads.clone();

        let (idx, _) = self
            .vaults
            .entry(vid)
            .and_modify(|(_, rids)| {
                rids.push(rid);
            })
            .or_insert((0, vec![rid]));

        if heads.len() <= *idx {
            heads.push(rid);
        } else {
            heads[*idx] = rid;
        }

        if !heads.contains(&rid) {
            heads.push(rid);
        }

        self.heads = heads;

        rid
    }

    /// Get the head of a vault.
    pub fn get_head(&self, vid: VaultId) -> RecordId {
        let (idx, _) = self.vaults.get(&vid).expect(line_error!("Vault doesn't exist"));

        self.heads[*idx]
    }

    /// Empty the Client Cache.
    pub fn clear_cache(&mut self) -> Option<()> {
        self.heads = vec![];
        self.vaults = HashMap::default();

        Some(())
    }

    pub fn rebuild_cache(&mut self, vids: Vec<VaultId>, rids: Vec<Vec<RecordId>>) {
        let iter = vids.iter().zip(rids.iter());

        for (v, rs) in iter {
            rs.iter().for_each(|r| {
                self.insert_record(*v, *r);
            });
        }
    }

    pub fn derive_vault_id(&self, path: Vec<u8>) -> VaultId {
        let data: Vec<u8> = self.id.into();

        VaultId::load(&data).expect(line_error!(""))
    }

    pub fn derive_record_id(&self, path: Vec<u8>) -> RecordId {
        let data: Vec<u8> = self.id.into();

        RecordId::load(&data).expect(line_error!(""))
    }
}

// /// Actor Factor for the Client Struct.
// impl ActorFactoryArgs<(ChannelRef<SHResults>, Vec<u8>, Vec<u8>)> for Client {
//     fn create_args((chan, data, path): (ChannelRef<SHResults>, Vec<u8>, Vec<u8>)) -> Self {
//         Client::new(chan, data, path)
//     }
// }

// /// Actor implementation for the Client.
// impl Actor for Client {
//     type Msg = ClientMsg;

//     // set up the channel.
//     // TODO: Make Topic random to create a handshake.
//     fn pre_start(&mut self, ctx: &Context<Self::Msg>) {
//         let sub = Box::new(ctx.myself());

//         let topic = Topic::from("external");

//         self.chan.tell(Subscribe { actor: sub, topic }, None);

//         let interal_actor = ctx.select("/user/internal-actor/").expect(line_error!());

//         let rid = self.derive_record_id(self.id.into());
//         let vid = self.derive_vault_id(self.id.into());

//         if let Some(data) = self.key_data {
//             interal_actor.try_tell(InternalMsg::StoreKeyData(vid, rid, data), None);
//         }
//     }

//     fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
//         self.receive(ctx, msg, sender);
//     }
// }

// /// Client Receive Block.
// impl Receive<SHRequest> for Client {
//     type Msg = ClientMsg;

//     fn receive(&mut self, ctx: &Context<Self::Msg>, msg: SHRequest, _sender: Sender) {
//         match msg {
//             SHRequest::CreateNewVault(vpath) => {
//                 let vid = VaultId::random::<Provider>().expect(line_error!());

//                 let keystore = ctx.select("/user/internal-actor/").expect(line_error!());

//                 keystore.try_tell(InternalMsg::CreateVault(vid), None);
//             }
//             SHRequest::ReadData(vpath, rpath) => {
//                 let keystore = ctx.select("/user/internal-actor/").expect(line_error!());

//                 if let Some(rid) = rid {
//                     keystore.try_tell(InternalMsg::ReadData(vid, rid), None);
//                 } else {
//                     let rid = self.get_head(vid);

//                     keystore.try_tell(InternalMsg::ReadData(vid, rid), None);
//                 }
//             }
//             SHRequest::InitRecord(vpath) => {
//                 let keystore = ctx.select("/user/internal-actor/").expect(line_error!());

//                 keystore.try_tell(InternalMsg::InitRecord(vid), None);
//             }
//             SHRequest::WriteData(vpath, rpath, payload, hint) => {
//                 let keystore = ctx.select("/user/internal-actor/").expect(line_error!());
//                 if let Some(rid) = rid {
//                     keystore.try_tell(InternalMsg::WriteData(vid, rid, payload, hint), None);
//                 } else {
//                     let rid = self.get_head(vid);

//                     keystore.try_tell(InternalMsg::WriteData(vid, rid, payload, hint), None);
//                 }
//             }
//             SHRequest::RevokeData(vpath, rpath) => {
//                 let keystore = ctx.select("/user/internal-actor/").expect(line_error!());

//                 keystore.try_tell(InternalMsg::RevokeData(vid, rid), None);
//             }
//             SHRequest::GarbageCollect(vpath) => {
//                 let keystore = ctx.select("/user/internal-actor/").expect(line_error!());

//                 keystore.try_tell(InternalMsg::GarbageCollect(vid), None);
//             }
//             SHRequest::ListIds(vpath) => {
//                 let keystore = ctx.select("/user/internal-actor/").expect(line_error!());

//                 keystore.try_tell(InternalMsg::ListIds(vid), None);
//             }
//             SHRequest::WriteSnapshot(pass, name, path) => {
//                 let bucket = ctx.select("/user/internal-actor/").expect(line_error!());

//                 bucket.try_tell(InternalMsg::WriteSnapshot(pass, name, path), None);
//             }
//             SHRequest::ReadSnapshot(pass, name, path) => {
//                 let bucket = ctx.select("/user/internal-actor/").expect(line_error!());

//                 bucket.try_tell(InternalMsg::ReadSnapshot(pass, name, path), None);
//             }
//             SHRequest::ClearCache => {
//                 let bucket = ctx.select("/user/internal-actor/").expect(line_error!());

//                 bucket.try_tell(InternalMsg::ClearCache, None);
//             }
//             SHRequest::ControlRequest(procedure) => match procedure {
//                 Procedure::SIP10 {
//                     seed,
//                     vault_path,
//                     record_path,
//                     hint,
//                 } => {
//                     let runtime = ctx.select("/user/runtime/").expect(line_error!());

//                     runtime.try_tell(
//                         RMsg::Slip10GenerateKey {
//                             seed,
//                             vault_id,
//                             record_id,
//                             hint,
//                         },
//                         None,
//                     );
//                 }
//             },
//         }
//     }
// }

// impl Receive<InternalResults> for Client {
//     type Msg = ClientMsg;

//     fn receive(&mut self, _ctx: &Context<Self::Msg>, msg: InternalResults, _sender: Sender) {
//         match msg {
//             InternalResults::ReturnCreateVault(vid, rid) => {
//                 let (vid, rid) = self.add_vault(vid, rid);

//                 let topic = Topic::from("external");

//                 self.chan.tell(
//                     Publish {
//                         msg: SHResults::ReturnCreate(vid, rid),
//                         topic,
//                     },
//                     None,
//                 )
//             }
//             InternalResults::ReturnInitRecord(vid, rid) => {
//                 self.insert_record(vid, rid);

//                 let topic = Topic::from("external");

//                 self.chan.tell(
//                     Publish {
//                         msg: SHResults::ReturnInit(vid, rid),
//                         topic,
//                     },
//                     None,
//                 )
//             }
//             InternalResults::ReturnReadData(payload) => {
//                 let topic = Topic::from("external");

//                 self.chan.tell(
//                     Publish {
//                         msg: SHResults::ReturnRead(payload),
//                         topic,
//                     },
//                     None,
//                 )
//             }
//             InternalResults::ReturnList(list) => {
//                 let topic = Topic::from("external");

//                 self.chan.tell(
//                     Publish {
//                         msg: SHResults::ReturnList(list),
//                         topic,
//                     },
//                     None,
//                 )
//             }
//             InternalResults::RebuildCache(vids, rids) => {
//                 self.clear_cache();
//                 self.rebuild_cache(vids.clone(), rids.clone());

//                 let topic = Topic::from("external");

//                 self.chan.tell(
//                     Publish {
//                         msg: SHResults::ReturnRebuild(vids, rids),
//                         topic,
//                     },
//                     None,
//                 );
//             }
//         }
//     }
// }

// // Receive to enable the channel.
// impl Receive<SHResults> for Client {
//     type Msg = ClientMsg;

//     fn receive(&mut self, _ctx: &Context<Self::Msg>, _msg: SHResults, _sender: Sender) {}
// }

#[cfg(test)]
mod test {
    use super::*;

    use crate::{client::Client, provider::Provider};

    #[test]
    fn test_add() {
        let vid = VaultId::random::<Provider>().expect(line_error!());
        let rid = RecordId::random::<Provider>().expect(line_error!());

        let mut cache = Client::new(b"key_data".to_vec(), b"client_path".to_vec());

        cache.add_vault(vid, rid);

        assert_eq!(cache.heads.len(), 1);
        assert_eq!(cache.heads[0], rid);
        assert_eq!(cache.vaults.get(&vid), Some(&(0usize, vec![rid])));

        let vid = VaultId::random::<Provider>().expect(line_error!());
        let rid = RecordId::random::<Provider>().expect(line_error!());

        cache.add_vault(vid, rid);

        assert_eq!(cache.heads.len(), 2);
        assert_eq!(cache.heads[1], rid);
        assert_eq!(cache.vaults.get(&vid), Some(&(1usize, vec![rid])));
    }

    #[test]
    fn test_insert() {
        let vid = VaultId::random::<Provider>().expect(line_error!());
        let rid = RecordId::random::<Provider>().expect(line_error!());

        let mut cache = Client::new(b"key_data".to_vec(), b"client_path".to_vec());

        cache.insert_record(vid, rid);

        assert_eq!(cache.heads.len(), 1);
        assert_eq!(cache.heads[0], rid);
        assert_eq!(cache.vaults.get(&vid), Some(&(0usize, vec![rid])));

        let rid2 = RecordId::random::<Provider>().expect(line_error!());

        cache.insert_record(vid, rid2);

        assert_eq!(cache.heads.len(), 1);
        assert_eq!(cache.heads[0], rid2);

        assert_eq!(cache.vaults.get(&vid), Some(&(0usize, vec![rid, rid2])));

        let vid2 = VaultId::random::<Provider>().expect(line_error!());
        let rid3 = RecordId::random::<Provider>().expect(line_error!());
        let rid4 = RecordId::random::<Provider>().expect(line_error!());

        cache.add_vault(vid2, rid3);
        cache.insert_record(vid2, rid4);

        assert_eq!(cache.heads.len(), 2);
        assert_eq!(cache.heads[1], rid4);

        assert_eq!(cache.vaults.get(&vid2), Some(&(1usize, vec![rid3, rid4])));
    }

    // #[test]
    // fn test_get_head_and_vault() {
    //     let vid = VaultId::random::<Provider>().expect(line_error!());
    //     let vid2 = VaultId::random::<Provider>().expect(line_error!());

    //     let rid = RecordId::random::<Provider>().expect(line_error!());
    //     let rid2 = RecordId::random::<Provider>().expect(line_error!());
    //     let rid3 = RecordId::random::<Provider>().expect(line_error!());
    //     let rid4 = RecordId::random::<Provider>().expect(line_error!());

    //     let sys = ActorSystem::new().unwrap();
    //     let chan: ChannelRef<SHResults> = channel("external", &sys).unwrap();

    //     let mut cache = Client::new(chan, b"key_data".to_vec(), b"client_path".to_vec());

    //     cache.add_vault(vid, rid);
    //     cache.insert_record(vid, rid2);
    //     cache.add_vault(vid2, rid3);
    //     cache.insert_record(vid2, rid4);

    //     let head0 = cache.get_head(vid);
    //     let head1 = cache.get_head(vid2);

    //     assert_eq!(head0, rid2);
    //     assert_eq!(head1, rid4);
    // }
}
