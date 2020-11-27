// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

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
#[actor(SHResponses, SHResults)]
pub struct Client {
    id: ClientId,
    // Contains the vault ids and the record ids with their associated indexes.
    vaults: HashMap<VaultId, (usize, Vec<RecordId>)>,
    // Contains the Record Ids for the most recent Record in each vault.
    heads: Vec<RecordId>,
    // Contains the VaultIds in order of creation.
    index: Vec<VaultId>,

    chan: ChannelRef<SHResults>,
}

// /// Messages to interact with Stronghold
// #[derive(Clone, Debug)]
// pub enum StrongholdMessage {
//     CreateNewVault,
//     ReturnCreateVault(VaultId, RecordId),
//     WriteData(usize, Vec<u8>, RecordHint),
//     InitRecord(usize),
//     ReturnInitRecord(VaultId, RecordId),
//     ReturnReadData(Vec<u8>),
//     ReadData(usize),
//     RevokeData(usize),
//     GarbageCollect(usize),
//     ListIds(usize),
//     ReturnList(Vec<(RecordId, RecordHint)>),
//     WriteSnapshot(String, Option<PathBuf>),
//     ReadSnapshot(String, Option<PathBuf>),
//     SetExternalActorPath(Option<String>),
// }

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct SHResults {
    return_create: Option<(VaultId, RecordId)>,
    return_init: Option<usize>,
    return_read: Option<Vec<u8>>,
    read_list: Option<Vec<(RecordId, RecordHint)>>,
}

/// Create a new Client.
impl Client {
    pub fn new(id: ClientId, chan: ChannelRef<SHResults>) -> Self {
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

        self.vaults.insert(vid, (idx, vec![rid]));
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
            .or_insert((0, vec![rid]));

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
            let (idx, _) = self.vaults.get(&vid).expect(line_error!());

            Some(*idx)
        } else {
            None
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

#[cfg(test)]
mod test {
    use super::*;

    use crate::{bucket::Bucket, client::Client, key_store::KeyStore, provider::Provider, snapshot::Snapshot};

    // #[derive(Clone, Debug)]
    // pub enum TestMsg {
    //     CreateVault,
    //     ReturnCreateVault(VaultId, RecordId),
    //     WriteData(usize, Vec<u8>, RecordHint),
    //     InitRecord(usize),
    //     InitRecordReturn(VaultId, RecordId),
    //     ReturnReadData(Vec<u8>),
    //     ReadData(usize),
    //     RevokeData(usize),
    //     GarbageCollect(usize),
    //     ListIds(usize),
    //     ReturnList(Vec<(RecordId, RecordHint)>),
    //     WriteSnapshot(String, Option<PathBuf>),
    //     ReadSnapshot(String, Option<PathBuf>),
    // }

    #[actor(SHResponses, SHResults)]
    pub struct MockExternal {
        vaults: HashMap<VaultId, Vec<RecordId>>,
        index: Vec<VaultId>,
    }

    impl Actor for MockExternal {
        type Msg = MockExternalMsg;

        fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
            self.receive(ctx, msg, sender);
        }
    }

    impl ActorFactoryArgs<HashMap<VaultId, Vec<RecordId>>> for MockExternal {
        fn create_args(vaults: HashMap<VaultId, Vec<RecordId>>) -> Self {
            let index = Vec::new();

            Self { vaults, index }
        }
    }

    impl Receive<SHResults> for MockExternal {
        type Msg = MockExternalMsg;

        fn receive(&mut self, ctx: &Context<Self::Msg>, msg: SHResults, sender: Sender) {}
    }

    impl Receive<SHResponses> for MockExternal {
        type Msg = MockExternalMsg;

        fn receive(&mut self, ctx: &Context<Self::Msg>, msg: SHResponses, sender: Sender) {}
    }

    #[test]
    fn test_add() {
        let vid = VaultId::random::<Provider>().expect(line_error!());
        let rid = RecordId::random::<Provider>().expect(line_error!());

        let sys = ActorSystem::new().unwrap();
        let chan: ChannelRef<SHResults> = channel("external", &sys).unwrap();

        let mut cache = Client::new(ClientId::random::<Provider>().expect(line_error!()), chan);

        cache.add_vault(vid, rid);

        assert_eq!(cache.index.len(), 1);
        assert_eq!(cache.heads.len(), 1);
        assert_eq!(cache.index[0], vid);
        assert_eq!(cache.heads[0], rid);
        assert_eq!(cache.vaults.get(&vid), Some(&(0usize, vec![rid])));

        let vid = VaultId::random::<Provider>().expect(line_error!());
        let rid = RecordId::random::<Provider>().expect(line_error!());

        cache.add_vault(vid, rid);

        assert_eq!(cache.index.len(), 2);
        assert_eq!(cache.heads.len(), 2);
        assert_eq!(cache.index[1], vid);
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

        assert_eq!(cache.index.len(), 1);
        assert_eq!(cache.heads.len(), 1);
        assert_eq!(cache.index[0], vid);
        assert_eq!(cache.heads[0], rid);
        assert_eq!(cache.vaults.get(&vid), Some(&(0usize, vec![rid])));

        let rid2 = RecordId::random::<Provider>().expect(line_error!());

        cache.insert_record(vid, rid2);

        assert_eq!(cache.index.len(), 1);
        assert_eq!(cache.heads.len(), 1);
        assert_eq!(cache.heads[0], rid2);
        assert_eq!(cache.index[0], vid);
        assert_eq!(cache.vaults.get(&vid), Some(&(0usize, vec![rid, rid2])));

        let vid2 = VaultId::random::<Provider>().expect(line_error!());
        let rid3 = RecordId::random::<Provider>().expect(line_error!());
        let rid4 = RecordId::random::<Provider>().expect(line_error!());

        cache.add_vault(vid2, rid3);
        cache.insert_record(vid2, rid4);

        assert_eq!(cache.index.len(), 2);
        assert_eq!(cache.heads.len(), 2);
        assert_eq!(cache.heads[1], rid4);
        assert_eq!(cache.index[1], vid2);
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

        let head0 = cache.get_head(0);
        let head1 = cache.get_head(1);
        let head2 = cache.get_head(2);

        assert_eq!(head0, Some(rid2));
        assert_eq!(head1, Some(rid4));
        assert_eq!(head2, None);

        let vault0 = cache.get_vault(0);
        let vault1 = cache.get_vault(1);
        let vault2 = cache.get_vault(3);

        assert_eq!(vault0, Some(vid));
        assert_eq!(vault1, Some(vid2));
        assert_eq!(vault2, None);
    }

    #[test]
    fn test_actor_model() {
        let sys = ActorSystem::new().unwrap();
        let chan: ChannelRef<SHResults> = channel("external", &sys).unwrap();

        let client = sys.actor_of_args::<Client, _>("client", chan.clone()).unwrap();
        sys.actor_of::<Bucket<Provider>>("bucket").unwrap();
        sys.actor_of::<KeyStore<Provider>>("keystore").unwrap();
        sys.actor_of::<Snapshot>("snapshot").unwrap();
    }
}
