// TODO: Synchronization via 4th actor and status type.
// TODO: Add supervisors
// TODO: Add documentation

use riker::actors::*;

use std::{fmt::Debug, path::PathBuf};

use engine::vault::{BoxProvider, Key, RecordHint, RecordId};

use crate::{
    bucket::Bucket, client::ClientMsg, ids::VaultId, key_store::KeyStore, line_error, provider::Provider,
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

#[derive(Debug, Clone)]
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

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
pub enum SMsg {
    WriteSnapshot(String, Option<PathBuf>, Vec<u8>),
    ReadSnapshot(String, Option<PathBuf>),
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
                client.try_tell(ClientMsg::CreateVaultReturn(vid, rid), None);
            }
            BMsg::ReadData(key, rid) => {
                let plain = self.read_data(key, rid);

                let client = ctx.select("/user/client/").expect(line_error!());
                client.try_tell(ClientMsg::ReadDataReturn(plain), None);
            }
            BMsg::WriteData(key, rid, payload, hint) => {
                self.write_payload(key, rid, payload, hint);
            }
            BMsg::InitRecord(key, vid) => {
                let rid = self.init_record(key);

                let client = ctx.select("/user/client/").expect(line_error!());
                client.try_tell(ClientMsg::InitRecordReturn(vid, rid), None);
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
                client.try_tell(ClientMsg::ListReturn(ids), None);
            }
            BMsg::WriteSnapshot(pass, path) => {
                let state = self.offload_data();

                let snapshot = ctx.select("/user/snapshot/").expect(line_error!());
                snapshot.try_tell(SMsg::WriteSnapshot(pass, path, state), None);
            }
            BMsg::ReadSnapshot(pass, path) => {
                let snapshot = ctx.select("/user/snapshot/").expect(line_error!());
                snapshot.try_tell(SMsg::ReadSnapshot(pass, path), None);
            }
            BMsg::ReloadData(state) => {
                let keys = self.repopulate_data(state);

                let keystore = ctx.select("/user/keystore/").expect(line_error!());
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

            KMsg::RebuildKeys(keys) => {
                self.rebuild_keystore(keys);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::client::Client;

    use std::collections::HashMap;

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
                    client.try_tell(ClientMsg::CreateVaultAsk, None);
                }
                TestMsg::ReturnCreateVault(vid, rid) => {
                    self.vaults.insert(vid, vec![rid]);

                    self.index.push(vid);
                }
                TestMsg::WriteData(index, payload, hint) => {
                    if index >= self.index.len() {
                        let external = ctx.select("/user/external").expect(line_error!());
                        external.try_tell(TestMsg::WriteData(index, payload.clone(), hint), None);
                    } else {
                        let vid = self.index[index];

                        let rids = self.vaults.get(&vid).expect(line_error!());
                        let rid = rids.last().expect(line_error!());

                        let client = ctx.select("/user/client/").expect(line_error!());
                        client.try_tell(ClientMsg::WriteData(vid, *rid, payload, hint), None);
                    }
                }
                TestMsg::InitRecord(index) => {
                    if index >= self.index.len() {
                        let external = ctx.select("/user/external").expect(line_error!());
                        external.try_tell(TestMsg::InitRecord(index), None);
                    } else {
                        let vid = self.index[index];

                        let client = ctx.select("/user/client/").expect(line_error!());
                        client.try_tell(ClientMsg::InitRecord(vid), None);
                    }
                }
                TestMsg::InitRecordReturn(vid, rid) => {
                    self.vaults.entry(vid).and_modify(|records| records.push(rid));

                    println!("{:?} {:?}", rid, vid);
                }
                TestMsg::ReadData(index) => {
                    if index >= self.index.len() {
                        let external = ctx.select("/user/external").expect(line_error!());
                        external.try_tell(TestMsg::ReadData(index), None);
                    } else {
                        let vid = self.index[index];

                        let rids = self.vaults.get(&vid).expect(line_error!());
                        match rids.last() {
                            Some(rid) => {
                                let client = ctx.select("/user/client/").expect(line_error!());
                                client.try_tell(ClientMsg::ReadDataAsk(vid, *rid), None);
                            }
                            None => {}
                        }
                    }
                }
                TestMsg::ReturnReadData(data) => {
                    println!("Plaintext Data: {:?}", std::str::from_utf8(&data));
                }
                TestMsg::RevokeData(index) => {
                    if index >= self.index.len() {
                        let external = ctx.select("/user/external").expect(line_error!());
                        external.try_tell(TestMsg::RevokeData(index), None);
                    } else {
                        let vid = self.index[index];

                        let rids = self.vaults.get_mut(&vid).expect(line_error!());
                        let rid = rids.pop().expect(line_error!());

                        let client = ctx.select("/user/client/").expect(line_error!());
                        client.try_tell(ClientMsg::RevokeData(vid, rid), None);
                    }
                }
                TestMsg::GarbageCollect(index) => {
                    if index >= self.index.len() {
                        let external = ctx.select("/user/external").expect(line_error!());
                        external.try_tell(TestMsg::GarbageCollect(index), None);
                    } else {
                        let vid = self.index[index];

                        let client = ctx.select("/user/client/").expect(line_error!());
                        client.try_tell(ClientMsg::GarbageCollect(vid), None);
                    }
                }
                TestMsg::ListIds(index) => {
                    if index >= self.index.len() {
                        let external = ctx.select("/user/external").expect(line_error!());
                        external.try_tell(TestMsg::ListIds(index), None);
                    } else {
                        let vid = self.index[index];

                        let client = ctx.select("/user/client/").expect(line_error!());
                        client.try_tell(ClientMsg::ListAsk(vid), None);
                    }
                }
                TestMsg::ReturnList(ids) => {
                    ids.iter().for_each(|(id, hint)| {
                        println!("Record Id: {:?}, Hint: {:?}", id, hint);
                    });
                }
                TestMsg::WriteSnapshot(pass, path) => {
                    let client = ctx.select("/user/client/").expect(line_error!());
                    client.try_tell(ClientMsg::WriteSnapshot(pass, path), None);
                }
                TestMsg::ReadSnapshot(pass, path) => {
                    let client = ctx.select("/user/client/").expect(line_error!());
                    client.try_tell(ClientMsg::ReadSnapshot(pass, path), None);
                }
            }
        }
    }

    #[test]
    fn test_actor_system() {
        let external_path = "/user/external/";
        let sys = ActorSystem::new().unwrap();
        let client = sys.actor_of::<Client>("client").unwrap();
        sys.actor_of::<Bucket<Provider>>("bucket").unwrap();
        sys.actor_of::<KeyStore<Provider>>("keystore").unwrap();
        sys.actor_of::<Snapshot>("snapshot").unwrap();
        let external_hashmap = HashMap::new();
        let external = sys
            .actor_of_args::<MockExternalActor, _>("external", external_hashmap)
            .unwrap();

        client.tell(ClientMsg::SetExternalActorName(String::from(external_path)), None);

        external.tell(TestMsg::CreateVault, None);

        std::thread::sleep(std::time::Duration::from_millis(5));

        external.tell(
            TestMsg::WriteData(0, b"Some Data".to_vec(), RecordHint::new(b"").expect(line_error!())),
            None,
        );

        external.tell(TestMsg::ListIds(0), None);

        external.tell(TestMsg::ReadData(0), None);

        external.tell(TestMsg::CreateVault, None);

        std::thread::sleep(std::time::Duration::from_millis(5));

        external.tell(
            TestMsg::WriteData(
                1,
                b"Some other data".to_vec(),
                RecordHint::new(b"").expect(line_error!()),
            ),
            None,
        );

        external.tell(TestMsg::ListIds(1), None);

        external.tell(TestMsg::ReadData(1), None);

        external.tell(TestMsg::InitRecord(1), None);

        external.tell(
            TestMsg::WriteData(
                1,
                b"even more data".to_vec(),
                RecordHint::new(b"").expect(line_error!()),
            ),
            None,
        );

        external.tell(TestMsg::ReadData(1), None);

        external.tell(TestMsg::InitRecord(0), None);

        external.tell(
            TestMsg::WriteData(
                0,
                b"A bit more data".to_vec(),
                RecordHint::new(b"").expect(line_error!()),
            ),
            None,
        );

        external.tell(TestMsg::ReadData(0), None);

        external.tell(TestMsg::WriteSnapshot("password".into(), None), None);

        external.tell(TestMsg::RevokeData(0), None);

        external.tell(TestMsg::ReadData(0), None);

        external.tell(TestMsg::ReadSnapshot("password".into(), None), None);

        external.tell(TestMsg::ReadData(0), None);

        std::thread::sleep(std::time::Duration::from_millis(2000));
        sys.print_tree();
    }
}
