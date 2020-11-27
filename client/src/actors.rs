use riker::actors::*;

use std::{fmt::Debug, path::PathBuf};

use engine::vault::{BoxProvider, Key, RecordHint, RecordId};

use crate::{
    bucket::Bucket, client::StrongholdMessage, ids::VaultId, key_store::KeyStore, line_error, provider::Provider,
    snapshot::Snapshot,
};

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
                client.try_tell(StrongholdMessage::ReturnCreateVault(vid, rid), None);
            }
            BMsg::ReadData(key, rid) => {
                let plain = self.read_data(key, rid);

                let client = ctx.select("/user/client/").expect(line_error!());
                client.try_tell(StrongholdMessage::ReturnReadData(plain), None);
            }
            BMsg::WriteData(key, rid, payload, hint) => {
                self.write_payload(key, rid, payload, hint);
            }
            BMsg::InitRecord(key, vid) => {
                let rid = self.init_record(key);

                let client = ctx.select("/user/client/").expect(line_error!());
                client.try_tell(StrongholdMessage::ReturnInitRecord(vid, rid), None);
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
                client.try_tell(StrongholdMessage::ReturnList(ids), None);
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

// #[cfg(test)]
// mod test {
// use super::*;

// use crate::client::Client;

// use std::collections::HashMap;

// #[test]
// fn test_actor_system() {
// let sys = ActorSystem::new().unwrap();
// let client = sys.actor_of::<Client>("client").unwrap();
// sys.actor_of::<Bucket<Provider>>("bucket").unwrap();
// sys.actor_of::<KeyStore<Provider>>("keystore").unwrap();
// sys.actor_of::<Snapshot>("snapshot").unwrap();

// external.tell(TestMsg::CreateVault, None);

// std::thread::sleep(std::time::Duration::from_millis(5));

// external.tell(
//     TestMsg::WriteData(0, b"Some Data".to_vec(), RecordHint::new(b"").expect(line_error!())),
//     None,
// );

// external.tell(TestMsg::ListIds(0), None);

// external.tell(TestMsg::ReadData(0), None);

// external.tell(TestMsg::CreateVault, None);

// std::thread::sleep(std::time::Duration::from_millis(5));

// external.tell(
//     TestMsg::WriteData(
//         1,
//         b"Some other data".to_vec(),
//         RecordHint::new(b"").expect(line_error!()),
//     ),
//     None,
// );

// external.tell(TestMsg::ListIds(1), None);

// external.tell(TestMsg::ReadData(1), None);

// external.tell(TestMsg::InitRecord(1), None);

// external.tell(
//     TestMsg::WriteData(
//         1,
//         b"even more data".to_vec(),
//         RecordHint::new(b"").expect(line_error!()),
//     ),
//     None,
// );

// external.tell(TestMsg::ReadData(1), None);

// external.tell(TestMsg::InitRecord(0), None);

// external.tell(
//     TestMsg::WriteData(
//         0,
//         b"A bit more data".to_vec(),
//         RecordHint::new(b"").expect(line_error!()),
//     ),
//     None,
// );

// external.tell(TestMsg::ReadData(0), None);

// external.tell(TestMsg::WriteSnapshot("password".into(), None), None);

// external.tell(TestMsg::RevokeData(0), None);

// external.tell(TestMsg::ReadData(0), None);

// std::thread::sleep(std::time::Duration::from_millis(2000));
// sys.print_tree();
//     }
// }
