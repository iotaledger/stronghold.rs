// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    actors::{BMsg, KMsg},
    ids::{ClientId, VaultId},
    line_error,
    provider::Provider,
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

/// Messages to interact with Stronghold
#[derive(Clone, Debug)]
pub enum SHRequest {
    CreateNewVault,
    WriteData(VaultId, Option<RecordId>, Vec<u8>, RecordHint),
    InitRecord(VaultId),
    ReadData(VaultId, Option<RecordId>),
    RevokeData(VaultId, RecordId),
    GarbageCollect(VaultId),
    ListIds(VaultId),
    WriteSnapshot(String, Option<String>, Option<PathBuf>),
    ReadSnapshot(String, Option<String>, Option<PathBuf>),
}

/// Messages that come from stronghold
#[derive(Clone, Debug)]
pub enum SHResults {
    ReturnCreate(VaultId, RecordId),
    ReturnInit(VaultId, RecordId),
    ReturnRead(Vec<u8>),
    ReturnList(Vec<(RecordId, RecordHint)>),
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

    #[derive(Clone, Debug)]
    pub enum InterfaceMsg {
        CreateVault,
        WriteData(usize, Option<usize>, Vec<u8>, RecordHint),
        InitRecord(usize),
        ReadData(usize, Option<usize>),
        RevokeData(usize, usize),
        GarbageCollect(usize),
        ListIds(usize),
        WriteSnapshot(String, Option<String>, Option<PathBuf>),
        ReadSnapshot(String, Option<String>, Option<PathBuf>),
    }

    #[derive(Clone, Debug)]
    pub struct StartTest {}

    #[actor(StartTest, InterfaceMsg)]
    pub struct TestActor {}

    #[actor(SHResults, InterfaceMsg)]
    pub struct MockExternal {
        chan: ChannelRef<SHResults>,
        vaults: Vec<VaultId>,
        records: Vec<Vec<RecordId>>,
    }

    impl Actor for TestActor {
        type Msg = TestActorMsg;

        fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
            self.receive(ctx, msg, sender);
        }
    }

    impl Actor for MockExternal {
        type Msg = MockExternalMsg;

        fn pre_start(&mut self, ctx: &Context<Self::Msg>) {
            let sub = Box::new(ctx.myself());
            let topic = Topic::from("external");
            self.chan.tell(Subscribe { actor: sub, topic }, None);
        }

        fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
            self.receive(ctx, msg, sender);
        }
    }

    impl ActorFactoryArgs<ChannelRef<SHResults>> for MockExternal {
        fn create_args(chan: ChannelRef<SHResults>) -> Self {
            let vaults = Vec::new();
            let records = Vec::new();

            Self { vaults, records, chan }
        }
    }

    impl ActorFactory for TestActor {
        fn create() -> Self {
            Self {}
        }
    }

    impl Receive<SHResults> for MockExternal {
        type Msg = MockExternalMsg;

        fn receive(&mut self, _ctx: &Context<Self::Msg>, msg: SHResults, _sender: Sender) {
            match msg {
                SHResults::ReturnCreate(vid, rid) => {
                    println!("Create Vault: {:?} with first record: {:?}", vid, rid);
                    self.vaults.push(vid);

                    self.records.push(vec![rid]);
                }
                SHResults::ReturnInit(vid, rid) => {
                    println!("Record {:?} Initialized at {:?} Vault", rid, vid);

                    let index = self.vaults.iter().position(|&v| v == vid).expect(line_error!());

                    let rids = &mut self.records[index];

                    rids.push(rid);
                }
                SHResults::ReturnList(list) => {
                    list.iter().for_each(|(rid, hint)| {
                        println!("Record: {:?}, Hint: {:?}", rid, hint);
                    });
                }
                SHResults::ReturnRead(data) => {
                    println!("Data Output: {}", std::str::from_utf8(&data).expect(line_error!()));
                }
                SHResults::ReturnRebuild(vids, rids) => {
                    println!("Read from snapshot and rebuilt table");

                    self.vaults.clear();

                    self.records.clear();

                    let iter = vids.iter().zip(rids.iter());

                    for (v, rs) in iter {
                        let mut rids = Vec::new();
                        rs.iter().for_each(|r| {
                            rids.push(*r);
                        });
                        self.vaults.push(*v);
                        self.records.push(rids);
                    }
                }
            }
        }
    }

    impl Receive<InterfaceMsg> for MockExternal {
        type Msg = MockExternalMsg;

        fn receive(&mut self, ctx: &Context<Self::Msg>, msg: InterfaceMsg, _sender: Sender) {
            match msg {
                InterfaceMsg::CreateVault => {
                    let client = ctx.select("/user/client/").expect(line_error!());

                    client.try_tell(ClientMsg::SHRequest(SHRequest::CreateNewVault), None);
                }
                InterfaceMsg::WriteData(vidx, ridx, payload, hint) => {
                    let client = ctx.select("/user/client/").expect(line_error!());

                    let rid = if let Some(ridx) = ridx {
                        let rids = self.records[vidx].clone();

                        Some(rids[ridx])
                    } else {
                        None
                    };

                    let vidx = self.vaults[vidx];

                    client.try_tell(
                        ClientMsg::SHRequest(SHRequest::WriteData(vidx, rid, payload, hint)),
                        None,
                    );
                }
                InterfaceMsg::InitRecord(vidx) => {
                    let client = ctx.select("/user/client/").expect(line_error!());

                    let vid = self.vaults[vidx];

                    client.try_tell(ClientMsg::SHRequest(SHRequest::InitRecord(vid)), None);
                }
                InterfaceMsg::ReadData(vidx, ridx) => {
                    let client = ctx.select("/user/client/").expect(line_error!());

                    let vid = self.vaults[vidx];

                    let rid = if let Some(ridx) = ridx {
                        let rids = self.records[vidx].clone();

                        Some(rids[ridx])
                    } else {
                        None
                    };

                    client.try_tell(ClientMsg::SHRequest(SHRequest::ReadData(vid, rid)), None);
                }
                InterfaceMsg::RevokeData(vidx, ridx) => {
                    let client = ctx.select("/user/client/").expect(line_error!());

                    let vid = self.vaults[vidx];

                    let rids = self.records[vidx].clone();

                    let rid = rids[ridx];

                    client.try_tell(ClientMsg::SHRequest(SHRequest::RevokeData(vid, rid)), None);
                }
                InterfaceMsg::GarbageCollect(vidx) => {
                    let client = ctx.select("/user/client/").expect(line_error!());

                    let vid = self.vaults[vidx];

                    client.try_tell(ClientMsg::SHRequest(SHRequest::GarbageCollect(vid)), None);
                }
                InterfaceMsg::ListIds(vidx) => {
                    let client = ctx.select("/user/client/").expect(line_error!());

                    let vid = self.vaults[vidx];

                    client.try_tell(ClientMsg::SHRequest(SHRequest::ListIds(vid)), None);
                }
                InterfaceMsg::WriteSnapshot(pass, name, path) => {
                    let client = ctx.select("/user/client/").expect(line_error!());

                    client.try_tell(ClientMsg::SHRequest(SHRequest::WriteSnapshot(pass, name, path)), None);
                }
                InterfaceMsg::ReadSnapshot(pass, name, path) => {
                    let client = ctx.select("/user/client/").expect(line_error!());

                    client.try_tell(ClientMsg::SHRequest(SHRequest::ReadSnapshot(pass, name, path)), None);
                }
            }
        }
    }

    impl Receive<StartTest> for TestActor {
        type Msg = TestActorMsg;

        fn receive(&mut self, ctx: &Context<Self::Msg>, _msg: StartTest, _sender: Sender) {
            let mock = ctx.select("/user/mock/").expect(line_error!());
            mock.try_tell(MockExternalMsg::InterfaceMsg(InterfaceMsg::CreateVault), None);

            std::thread::sleep(std::time::Duration::from_millis(5));

            mock.try_tell(
                MockExternalMsg::InterfaceMsg(InterfaceMsg::WriteData(
                    0,
                    None,
                    b"Some Data".to_vec(),
                    RecordHint::new(b"some_hint").expect(line_error!()),
                )),
                None,
            );

            mock.try_tell(MockExternalMsg::InterfaceMsg(InterfaceMsg::ReadData(0, None)), None);
            mock.try_tell(MockExternalMsg::InterfaceMsg(InterfaceMsg::ListIds(0)), None);

            mock.try_tell(MockExternalMsg::InterfaceMsg(InterfaceMsg::CreateVault), None);

            std::thread::sleep(std::time::Duration::from_millis(5));

            mock.try_tell(
                MockExternalMsg::InterfaceMsg(InterfaceMsg::WriteData(
                    1,
                    None,
                    b"Some more data".to_vec(),
                    RecordHint::new(b"key_data").expect(line_error!()),
                )),
                None,
            );

            mock.try_tell(MockExternalMsg::InterfaceMsg(InterfaceMsg::InitRecord(1)), None);

            std::thread::sleep(std::time::Duration::from_millis(5));

            mock.try_tell(
                MockExternalMsg::InterfaceMsg(InterfaceMsg::WriteData(
                    1,
                    None,
                    b"Even more data".to_vec(),
                    RecordHint::new(b"password").expect(line_error!()),
                )),
                None,
            );

            mock.try_tell(MockExternalMsg::InterfaceMsg(InterfaceMsg::ReadData(1, Some(0))), None);
            mock.try_tell(MockExternalMsg::InterfaceMsg(InterfaceMsg::ReadData(1, None)), None);

            mock.try_tell(MockExternalMsg::InterfaceMsg(InterfaceMsg::ListIds(1)), None);
            std::thread::sleep(std::time::Duration::from_millis(5));

            mock.try_tell(
                MockExternalMsg::InterfaceMsg(InterfaceMsg::WriteSnapshot("password".into(), None, None)),
                None,
            );
            std::thread::sleep(std::time::Duration::from_millis(300));

            mock.try_tell(MockExternalMsg::InterfaceMsg(InterfaceMsg::RevokeData(1, 0)), None);

            mock.try_tell(MockExternalMsg::InterfaceMsg(InterfaceMsg::RevokeData(1, 1)), None);

            mock.try_tell(MockExternalMsg::InterfaceMsg(InterfaceMsg::GarbageCollect(1)), None);

            mock.try_tell(
                MockExternalMsg::InterfaceMsg(InterfaceMsg::ReadSnapshot("password".into(), None, None)),
                None,
            );
            std::thread::sleep(std::time::Duration::from_millis(300));

            mock.try_tell(MockExternalMsg::InterfaceMsg(InterfaceMsg::ReadData(1, None)), None);

            mock.try_tell(MockExternalMsg::InterfaceMsg(InterfaceMsg::ReadData(1, Some(0))), None);
        }
    }

    impl Receive<InterfaceMsg> for TestActor {
        type Msg = TestActorMsg;

        fn receive(&mut self, _ctx: &Context<Self::Msg>, _msg: InterfaceMsg, _sender: Sender) {}
    }

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

    #[test]
    fn test_actor_model() {
        use crate::init_stronghold;

        let (sys, chan) = init_stronghold();

        sys.actor_of_args::<MockExternal, _>("mock", chan).expect(line_error!());

        let test = sys.sys_actor_of::<TestActor>("test").expect(line_error!());

        test.tell(StartTest {}, None);

        std::thread::sleep(std::time::Duration::from_millis(2000));
    }
}
