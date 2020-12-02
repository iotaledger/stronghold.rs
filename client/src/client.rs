// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    actors::{BMsg, KMsg},
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
#[actor(SHRequest, InternalResults, SHResults)]
pub struct Client {
    #[allow(dead_code)]
    id: ClientId,
    // Contains the vault ids and the record ids with their associated indexes.
    vaults: HashMap<VaultId, (usize, Vec<RecordId>)>,
    // Contains the Record Ids for the most recent Record in each vault.
    heads: Vec<RecordId>,
    // channel to receive data from stronghold.
    chan: ChannelRef<SHResults>,
}

#[derive(Debug, Clone)]
pub enum Procedure {
    SIP10 {
        seed: Vec<u8>,
        master_record: (VaultId, RecordId, RecordHint),
        secret_record: (VaultId, RecordId, RecordHint),
    },
}

/// Messages to interact with Stronghold
#[derive(Clone, Debug)]
pub enum SHRequest {
    // Creates a new Vault.
    CreateNewVault,
    // Writes data to a record in the vault.  Accepts the vault id, an optional record id, the payload and the record
    // hint.  If a record id is not specified, the write will default to the head of the vault.  Returns
    // `ReturnCreate`.
    WriteData(VaultId, Option<RecordId>, Vec<u8>, RecordHint),
    // Moves the head forward in the specified Vault and opens a new record.  Returns `ReturnInit`.
    InitRecord(VaultId),
    // Reads data from a record in the vault. Accepts a vault id and an optional record id.  If the record id is not
    // specified, it reads the head.  Returns with `ReturnRead`.
    ReadData(VaultId, Option<RecordId>),
    // Marks a Record for deletion.  Accepts a vault id and a record id.  Deletion only occurs after a
    // `GarbageCollect` is called.
    RevokeData(VaultId, RecordId),
    // Garbages collects any marked records on a Vault. Accepts the vault id.
    GarbageCollect(VaultId),
    // Lists all of the record ids and the record hints for the records in a vault.  Accepts a vault id and returns
    // with `ReturnList`.
    ListIds(VaultId),
    // Writes to the snapshot file.  Accepts the password, an optional filename and an optional filepath.  Defaults to
    // `$HOME/.engine/snapshots/backup.snapshot`.
    WriteSnapshot(String, Option<String>, Option<PathBuf>),
    // Reads from the snapshot file.  Accepts the password, an optional filename and an optional filepath.  Defaults
    // to `$HOME/.engine/snapshots/backup.snapshot`.
    ReadSnapshot(String, Option<String>, Option<PathBuf>),

    ControlRequest(Procedure),
}

/// Messages that come from stronghold
#[derive(Clone, Debug)]
pub enum SHResults {
    // Results from calling `CreateNewVault`.
    ReturnCreate(VaultId, RecordId),
    // Results from calling `InitRecord`.
    ReturnInit(VaultId, RecordId),
    // Results from calling `ReadData`
    ReturnRead(Vec<u8>),
    // Results from calling `ListIds`
    ReturnList(Vec<(RecordId, RecordHint)>),
    // Results from calling `ReadSnapshot`
    ReturnRebuild(Vec<VaultId>, Vec<Vec<RecordId>>),
}

/// Messages used internally by the client.
#[derive(Clone, Debug)]
pub enum InternalResults {
    ReturnCreateVault(VaultId, RecordId),
    ReturnInitRecord(VaultId, RecordId),
    ReturnReadData(Vec<u8>),
    ReturnList(Vec<(RecordId, RecordHint)>),
    RebuildCache(Vec<VaultId>, Vec<Vec<RecordId>>),
}

impl Client {
    /// Creates a new Client given a `ClientID` and `ChannelRef<SHResults>`
    pub fn new(id: ClientId, chan: ChannelRef<SHResults>) -> Self {
        let vaults = HashMap::new();
        let heads = Vec::new();

        Self {
            id,
            vaults,
            heads,
            chan,
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
}

/// Actor Factor for the Client Struct.
impl ActorFactoryArgs<ChannelRef<SHResults>> for Client {
    fn create_args(chan: ChannelRef<SHResults>) -> Self {
        Client::new(ClientId::random::<Provider>().expect(line_error!()), chan)
    }
}

/// Actor implementation for the Client.
impl Actor for Client {
    type Msg = ClientMsg;

    // set up the channel.
    // TODO: Make Topic random to create a handshake.
    fn pre_start(&mut self, ctx: &Context<Self::Msg>) {
        let sub = Box::new(ctx.myself());

        let topic = Topic::from("external");

        self.chan.tell(Subscribe { actor: sub, topic }, None);
    }

    fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        self.receive(ctx, msg, sender);
    }
}

/// Client Receive Block.
impl Receive<SHRequest> for Client {
    type Msg = ClientMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: SHRequest, _sender: Sender) {
        match msg {
            SHRequest::CreateNewVault => {
                let vid = VaultId::random::<Provider>().expect(line_error!());

                let keystore = ctx.select("/user/keystore/").expect(line_error!());

                keystore.try_tell(KMsg::CreateVault(vid), None);
            }
            SHRequest::ReadData(vid, rid) => {
                let keystore = ctx.select("/user/keystore/").expect(line_error!());

                if let Some(rid) = rid {
                    keystore.try_tell(KMsg::ReadData(vid, rid), None);
                } else {
                    let rid = self.get_head(vid);

                    keystore.try_tell(KMsg::ReadData(vid, rid), None);
                }
            }
            SHRequest::InitRecord(vid) => {
                let keystore = ctx.select("/user/keystore/").expect(line_error!());

                keystore.try_tell(KMsg::InitRecord(vid), None);
            }
            SHRequest::WriteData(vid, rid, payload, hint) => {
                let keystore = ctx.select("/user/keystore/").expect(line_error!());
                if let Some(rid) = rid {
                    keystore.try_tell(KMsg::WriteData(vid, rid, payload, hint), None);
                } else {
                    let rid = self.get_head(vid);

                    keystore.try_tell(KMsg::WriteData(vid, rid, payload, hint), None);
                }
            }
            SHRequest::RevokeData(vid, rid) => {
                let keystore = ctx.select("/user/keystore/").expect(line_error!());

                keystore.try_tell(KMsg::RevokeData(vid, rid), None);
            }
            SHRequest::GarbageCollect(vid) => {
                let keystore = ctx.select("/user/keystore/").expect(line_error!());

                keystore.try_tell(KMsg::GarbageCollect(vid), None);
            }
            SHRequest::ListIds(vid) => {
                let keystore = ctx.select("/user/keystore/").expect(line_error!());

                keystore.try_tell(KMsg::ListIds(vid), None);
            }
            SHRequest::WriteSnapshot(pass, name, path) => {
                let bucket = ctx.select("/user/bucket/").expect(line_error!());

                bucket.try_tell(BMsg::WriteSnapshot::<Provider>(pass, name, path), None);
            }
            SHRequest::ReadSnapshot(pass, name, path) => {
                let bucket = ctx.select("/user/bucket/").expect(line_error!());

                bucket.try_tell(BMsg::ReadSnapshot::<Provider>(pass, name, path), None);
            }
            SHRequest::ControlRequest(procedure) => match procedure {
                Procedure::SIP10 {
                    seed,
                    master_record,
                    secret_record,
                } => {
                    let runtime = ctx.select("/user/runtime/").expect(line_error!());

                    runtime.try_tell(
                        RMsg::Slip10GenerateKey {
                            seed,
                            master_record,
                            secret_record,
                        },
                        None,
                    );
                }
            },
        }
    }
}

impl Receive<InternalResults> for Client {
    type Msg = ClientMsg;

    fn receive(&mut self, _ctx: &Context<Self::Msg>, msg: InternalResults, _sender: Sender) {
        match msg {
            InternalResults::ReturnCreateVault(vid, rid) => {
                let (vid, rid) = self.add_vault(vid, rid);

                let topic = Topic::from("external");

                self.chan.tell(
                    Publish {
                        msg: SHResults::ReturnCreate(vid, rid),
                        topic,
                    },
                    None,
                )
            }
            InternalResults::ReturnInitRecord(vid, rid) => {
                self.insert_record(vid, rid);

                let topic = Topic::from("external");

                self.chan.tell(
                    Publish {
                        msg: SHResults::ReturnInit(vid, rid),
                        topic,
                    },
                    None,
                )
            }
            InternalResults::ReturnReadData(payload) => {
                let topic = Topic::from("external");

                self.chan.tell(
                    Publish {
                        msg: SHResults::ReturnRead(payload),
                        topic,
                    },
                    None,
                )
            }
            InternalResults::ReturnList(list) => {
                let topic = Topic::from("external");

                self.chan.tell(
                    Publish {
                        msg: SHResults::ReturnList(list),
                        topic,
                    },
                    None,
                )
            }
            InternalResults::RebuildCache(vids, rids) => {
                self.clear_cache();
                self.rebuild_cache(vids.clone(), rids.clone());

                let topic = Topic::from("external");

                self.chan.tell(
                    Publish {
                        msg: SHResults::ReturnRebuild(vids, rids),
                        topic,
                    },
                    None,
                );
            }
        }
    }
}

// Receive to enable the channel.
impl Receive<SHResults> for Client {
    type Msg = ClientMsg;

    fn receive(&mut self, _ctx: &Context<Self::Msg>, _msg: SHResults, _sender: Sender) {}
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::{client::Client, provider::Provider};

    #[test]
    fn test_add() {
        let vid = VaultId::random::<Provider>().expect(line_error!());
        let rid = RecordId::random::<Provider>().expect(line_error!());

        let sys = ActorSystem::new().unwrap();
        let chan: ChannelRef<SHResults> = channel("external", &sys).unwrap();

        let mut cache = Client::new(ClientId::random::<Provider>().expect(line_error!()), chan);

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

        let sys = ActorSystem::new().unwrap();
        let chan: ChannelRef<SHResults> = channel("external", &sys).unwrap();

        let mut cache = Client::new(ClientId::random::<Provider>().expect(line_error!()), chan);

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

    #[test]
    fn test_get_head_and_vault() {
        let vid = VaultId::random::<Provider>().expect(line_error!());
        let vid2 = VaultId::random::<Provider>().expect(line_error!());

        let rid = RecordId::random::<Provider>().expect(line_error!());
        let rid2 = RecordId::random::<Provider>().expect(line_error!());
        let rid3 = RecordId::random::<Provider>().expect(line_error!());
        let rid4 = RecordId::random::<Provider>().expect(line_error!());

        let sys = ActorSystem::new().unwrap();
        let chan: ChannelRef<SHResults> = channel("external", &sys).unwrap();

        let mut cache = Client::new(ClientId::random::<Provider>().expect(line_error!()), chan);

        cache.add_vault(vid, rid);
        cache.insert_record(vid, rid2);
        cache.add_vault(vid2, rid3);
        cache.insert_record(vid2, rid4);

        let head0 = cache.get_head(vid);
        let head1 = cache.get_head(vid2);

        assert_eq!(head0, rid2);
        assert_eq!(head1, rid4);
    }
}
