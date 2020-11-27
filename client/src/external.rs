// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use riker::actors::*;

use engine::vault::{RecordHint, RecordId};

use std::path::PathBuf;

use crate::{ids::VaultId, line_error};

use std::collections::HashMap;

pub struct CacheActor {
    // Contains the vault ids and the record ids with their associated indexes.
    vaults: HashMap<VaultId, (usize, Vec<RecordId>)>,
    // Contains the Record Ids for the most recent Record in each vault.
    heads: Vec<RecordId>,
    // Contains the VaultIds in order of creation.
    index: Vec<VaultId>,
    // Set the actor path for the cache actor which will talk with the Stronghold.
    external_actor_path: String,
}

/// Messages to interact with Stronghold
#[derive(Clone, Debug)]
pub enum StrongholdMessage {
    CreateNewVault,
    ReturnCreateVault(VaultId, RecordId),
    WriteData(usize, Vec<u8>, RecordHint),
    InitRecord(usize),
    ReturnInitRecord(VaultId, RecordId),
    ReturnReadData(Vec<u8>),
    ReadData(usize),
    RevokeData(usize),
    GarbageCollect(usize),
    ListIds(usize),
    ReturnList(Vec<(RecordId, RecordHint)>),
    WriteSnapshot(String, Option<PathBuf>),
    ReadSnapshot(String, Option<PathBuf>),
    SetExternalActorPath(Option<String>),
}

impl CacheActor {
    pub fn new() -> Self {
        let vaults = HashMap::new();
        let heads = Vec::new();
        let index = Vec::new();

        Self {
            vaults,
            heads,
            index,
            external_actor_path: String::from(""),
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

impl Actor for CacheActor {
    type Msg = StrongholdMessage;

    fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        self.receive(ctx, msg, sender);
    }
}

impl ActorFactory for CacheActor {
    fn create() -> Self {
        CacheActor::new()
    }
}

impl Receive<StrongholdMessage> for CacheActor {
    type Msg = StrongholdMessage;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, _sender: Sender) {
        match msg {
            StrongholdMessage::CreateNewVault => {}
            StrongholdMessage::ReturnCreateVault(vid, rid) => {}
            StrongholdMessage::WriteData(index, payload, hint) => {}
            StrongholdMessage::InitRecord(index) => {}
            StrongholdMessage::ReturnInitRecord(vid, rid) => {}
            StrongholdMessage::ReturnReadData(payload) => {}
            StrongholdMessage::ReadData(index) => {}
            StrongholdMessage::RevokeData(index) => {}
            StrongholdMessage::GarbageCollect(index) => {}
            StrongholdMessage::ListIds(index) => {}
            StrongholdMessage::ReturnList(records_and_hints) => {}
            StrongholdMessage::WriteSnapshot(pass, path) => {}
            StrongholdMessage::ReadSnapshot(pass, path) => {}
            StrongholdMessage::SetExternalActorPath(path) => {
                if let Some(p) = path {
                    self.external_actor_path = p;
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::{
        bucket::Bucket,
        client::{Client, ClientMsg},
        key_store::KeyStore,
        provider::Provider,
        snapshot::Snapshot,
    };

    #[derive(Clone, Debug)]
    pub enum TestMsg {
        CreateVault,
        ReturnCreateVault(VaultId, RecordId),
        WriteData(usize, Vec<u8>, RecordHint),
        InitRecord(usize),
        InitRecordReturn(VaultId, RecordId),
        ReturnReadData(Vec<u8>),
        ReadData(usize),
        RevokeData(usize),
        GarbageCollect(usize),
        ListIds(usize),
        ReturnList(Vec<(RecordId, RecordHint)>),
        WriteSnapshot(String, Option<PathBuf>),
        ReadSnapshot(String, Option<PathBuf>),
    }

    pub struct MockExternalActor {
        vaults: HashMap<VaultId, Vec<RecordId>>,
        index: Vec<VaultId>,
    }

    impl Actor for MockExternalActor {
        type Msg = TestMsg;

        fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
            self.receive(ctx, msg, sender);
        }
    }

    impl ActorFactoryArgs<HashMap<VaultId, Vec<RecordId>>> for MockExternalActor {
        fn create_args(vaults: HashMap<VaultId, Vec<RecordId>>) -> Self {
            let index = Vec::new();

            Self { vaults, index }
        }
    }

    impl Receive<TestMsg> for MockExternalActor {
        type Msg = TestMsg;

        fn receive(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, _sender: Sender) {
            match msg {
                TestMsg::CreateVault => {
                    let client = ctx.select("/user/client/").expect(line_error!());
                    client.try_tell(StrongholdMessage::CreateNewVault, None);
                }
                TestMsg::ReturnCreateVault(vid, rid) => {
                    self.vaults.insert(vid, vec![rid]);

                    self.index.push(vid);
                }
                TestMsg::WriteData(index, payload, hint) => {
                    let cache = ctx.select("/user/cache").expect(line_error!());
                    cache.try_tell(StrongholdMessage::WriteData(index, payload, hint), None);
                }
                TestMsg::InitRecord(index) => {
                    let client = ctx.select("/user/client/").expect(line_error!());
                    client.try_tell(StrongholdMessage::InitRecord(index), None);
                }
                TestMsg::InitRecordReturn(vid, rid) => {
                    println!("{:?} {:?}", rid, vid);
                }
                TestMsg::ReadData(index) => {
                    let cache = ctx.select("/user/cache").expect(line_error!());
                    cache.try_tell(StrongholdMessage::ReadData(index), None);
                }
                TestMsg::ReturnReadData(data) => {
                    println!("Plaintext Data: {:?}", std::str::from_utf8(&data));
                }
                TestMsg::RevokeData(index) => {
                    let cache = ctx.select("/user/cache").expect(line_error!());
                    cache.try_tell(StrongholdMessage::RevokeData(index), None);
                }
                TestMsg::GarbageCollect(index) => {
                    let cache = ctx.select("/user/cache").expect(line_error!());
                    cache.try_tell(StrongholdMessage::GarbageCollect(index), None);
                }
                TestMsg::ListIds(index) => {
                    let cache = ctx.select("/user/cache").expect(line_error!());
                    cache.try_tell(StrongholdMessage::ListIds(index), None);
                }
                TestMsg::ReturnList(ids) => {
                    ids.iter().for_each(|(id, hint)| {
                        println!("Record Id: {:?}, Hint: {:?}", id, hint);
                    });
                }
                TestMsg::WriteSnapshot(pass, path) => {
                    let client = ctx.select("/user/client/").expect(line_error!());
                    client.try_tell(StrongholdMessage::WriteSnapshot(pass, path), None);
                }
                TestMsg::ReadSnapshot(pass, path) => {
                    let client = ctx.select("/user/client/").expect(line_error!());
                    client.try_tell(StrongholdMessage::ReadSnapshot(pass, path), None);
                }
            }
        }
    }

    #[test]
    fn test_add() {
        let vid = VaultId::random::<Provider>().expect(line_error!());
        let rid = RecordId::random::<Provider>().expect(line_error!());

        let mut cache = CacheActor::new();

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

        let mut cache = CacheActor::new();

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

        let mut cache = CacheActor::new();

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
        let client = sys.actor_of::<Client>("client").unwrap();
        let cache = sys.actor_of::<CacheActor>("cache").unwrap();
        sys.actor_of::<Bucket<Provider>>("bucket").unwrap();
        sys.actor_of::<KeyStore<Provider>>("keystore").unwrap();
        sys.actor_of::<Snapshot>("snapshot").unwrap();
    }
}
