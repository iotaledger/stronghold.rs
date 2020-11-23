use riker::actors::*;

use std::fmt::Debug;

use engine::vault::{BoxProvider, Key, RecordHint, RecordId};

use crate::{
    bucket::Bucket,
    client::Client,
    ids::{ClientId, VaultId},
    key_store::KeyStore,
    line_error,
    provider::Provider,
};

#[derive(Debug, Clone)]
pub enum CMsg {
    SetExternalName(String),
    CreateVaultAsk,
    CreateVaultReturn(VaultId, RecordId),
    ReadDataAsk(VaultId, RecordId),
    ReadDataReturn(Vec<u8>),
    WriteData(VaultId, RecordId, Vec<u8>, RecordHint),
    CommitWrite(VaultId, RecordId),
    RevokeData(VaultId, RecordId),
    GarbageCollect(VaultId),
    ListAsk(VaultId),
    ListReturn(Vec<(RecordId, RecordHint)>),
}

#[derive(Debug, Clone)]
pub enum BMsg<P: BoxProvider + Debug> {
    CreateVault(VaultId, Key<P>),
    ReadData(Key<P>, RecordId),
    WriteData(Key<P>, RecordId, Vec<u8>, RecordHint),
    CommitWrite(Key<P>, RecordId),
    RevokeData(Key<P>, RecordId),
    GarbageCollect(Key<P>),
    ListAsk(Key<P>),
}

#[derive(Clone, Debug)]
pub enum KMsg {
    CreateVault(VaultId),
    ReadData(VaultId, RecordId),
    WriteData(VaultId, RecordId, Vec<u8>, RecordHint),
    CommitWrite(VaultId, RecordId),
    RevokeData(VaultId, RecordId),
    GarbageCollect(VaultId),
    ListIds(VaultId),
}

impl ActorFactory for Client {
    fn create() -> Self {
        Client::new(ClientId::random::<Provider>().expect(line_error!()), None)
    }
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

impl Actor for Client {
    type Msg = CMsg;

    fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        self.receive(ctx, msg, sender);
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

impl Receive<CMsg> for Client {
    type Msg = CMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, _sender: Sender) {
        match msg {
            CMsg::CreateVaultAsk => {
                let vid = VaultId::random::<Provider>().expect(line_error!());

                let kstore = ctx.select("/user/keystore/").expect(line_error!());
                kstore.try_tell(KMsg::CreateVault(vid), None);
            }
            CMsg::CreateVaultReturn(vid, rid) => {
                #[cfg(test)]
                let external = ctx
                    .select(self.external_actor.as_ref().expect(line_error!()))
                    .expect(line_error!());

                #[cfg(test)]
                external.try_tell(EMsg::ReturnCreateVault(vid, rid), None);
            }
            CMsg::ReadDataAsk(vid, rid) => {
                let kstore = ctx.select("/user/keystore/").expect(line_error!());
                kstore.try_tell(KMsg::ReadData(vid, rid), None);
            }
            CMsg::ReadDataReturn(data) => {
                #[cfg(test)]
                let external = ctx
                    .select(self.external_actor.as_ref().expect(line_error!()))
                    .expect(line_error!());

                #[cfg(test)]
                external.try_tell(EMsg::ReturnReadData(data), None);
            }
            CMsg::WriteData(vid, rid, payload, hint) => {
                let kstore = ctx.select("/user/keystore/").expect(line_error!());
                kstore.try_tell(KMsg::WriteData(vid, rid, payload, hint), None);
            }
            CMsg::CommitWrite(vid, rid) => {
                let kstore = ctx.select("/user/keystore/").expect(line_error!());
                kstore.try_tell(KMsg::CommitWrite(vid, rid), None);
            }
            CMsg::RevokeData(vid, rid) => {
                let kstore = ctx.select("/user/keystore/").expect(line_error!());
                kstore.try_tell(KMsg::RevokeData(vid, rid), None);
            }
            CMsg::GarbageCollect(vid) => {
                let kstore = ctx.select("/user/keystore/").expect(line_error!());
                kstore.try_tell(KMsg::GarbageCollect(vid), None);
            }
            CMsg::ListAsk(vid) => {
                let kstore = ctx.select("/user/keystore/").expect(line_error!());
                kstore.try_tell(KMsg::ListIds(vid), None);
            }
            CMsg::ListReturn(ids) => {
                println!("{:?}", ids);
                #[cfg(test)]
                let external = ctx
                    .select(self.external_actor.as_ref().expect(line_error!()))
                    .expect(line_error!());

                #[cfg(test)]
                external.try_tell(EMsg::ReturnList(ids), None);
            }
            CMsg::SetExternalName(id) => {
                self.external_actor = Some(id);
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
                client.try_tell(CMsg::CreateVaultReturn(vid, rid), None);
            }
            BMsg::ReadData(key, rid) => {
                let plain = self.read_data(key, rid);

                let client = ctx.select("/user/client/").expect(line_error!());
                client.try_tell(CMsg::ReadDataReturn(plain), None);
            }
            BMsg::WriteData(key, rid, payload, hint) => {
                self.write_payload(key, rid, payload, hint);
            }
            BMsg::CommitWrite(key, rid) => {
                self.commit_write(key, rid);
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
                client.try_tell(CMsg::ListReturn(ids), None);
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
            KMsg::CommitWrite(vid, rid) => {
                if let Some(key) = self.get_key(vid) {
                    let bucket = ctx.select("/user/bucket/").expect(line_error!());
                    bucket.try_tell(BMsg::CommitWrite(key.clone(), rid), None);

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
        }
    }
}

#[derive(Clone, Debug)]
pub enum EMsg {
    CreateVault,
    ReturnCreateVault(VaultId, RecordId),
    WriteData(usize, Vec<u8>, RecordHint),
    CommitWrite(usize),
    ReturnReadData(Vec<u8>),
    ReadData(usize),
    RevokeData(usize),
    GarbageCollect(usize),
    ListIds(usize),
    ReturnList(Vec<(RecordId, RecordHint)>),
}

pub struct MockExternalActor {
    vaults: Vec<(VaultId, RecordId)>,
}

impl Actor for MockExternalActor {
    type Msg = EMsg;

    fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        self.receive(ctx, msg, sender);
    }
}

impl ActorFactory for MockExternalActor {
    fn create() -> Self {
        let vaults = Vec::new();
        Self { vaults }
    }
}

impl Receive<EMsg> for MockExternalActor {
    type Msg = EMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, _sender: Sender) {
        match msg {
            EMsg::CreateVault => {
                let client = ctx.select("/user/client/").expect(line_error!());
                client.try_tell(CMsg::CreateVaultAsk, None);
            }
            EMsg::ReturnCreateVault(vid, rid) => {
                self.vaults.push((vid, rid));
            }
            EMsg::WriteData(index, payload, hint) => {
                if index >= self.vaults.len() {
                    let external = ctx.select("/user/external").expect(line_error!());
                    external.try_tell(EMsg::WriteData(index, payload.clone(), hint), None);
                } else {
                    let (vid, rid) = self.vaults[index];

                    let client = ctx.select("/user/client/").expect(line_error!());
                    client.try_tell(CMsg::WriteData(vid, rid, payload, hint), None);
                }
            }
            EMsg::CommitWrite(index) => {
                if index >= self.vaults.len() {
                    let external = ctx.select("/user/external").expect(line_error!());
                    external.try_tell(EMsg::CommitWrite(index), None);
                } else {
                    let (vid, rid) = self.vaults[index];

                    let client = ctx.select("/user/client/").expect(line_error!());
                    client.try_tell(CMsg::CommitWrite(vid, rid), None);
                }
            }
            EMsg::ReadData(index) => {
                if index >= self.vaults.len() {
                    let external = ctx.select("/user/external").expect(line_error!());
                    external.try_tell(EMsg::ReadData(index), None);
                } else {
                    let (vid, rid) = self.vaults[index];

                    let client = ctx.select("/user/client/").expect(line_error!());
                    client.try_tell(CMsg::ReadDataAsk(vid, rid), None);
                }
            }
            EMsg::ReturnReadData(data) => {
                println!("Plaintext Data: {:?}", std::str::from_utf8(&data));
            }
            EMsg::RevokeData(index) => {
                let (vid, rid) = self.vaults[index];

                let client = ctx.select("/user/client/").expect(line_error!());
                client.try_tell(CMsg::RevokeData(vid, rid), None);
            }
            EMsg::GarbageCollect(index) => {
                let (vid, _) = self.vaults[index];

                let client = ctx.select("/user/client/").expect(line_error!());
                client.try_tell(CMsg::GarbageCollect(vid), None);
            }
            EMsg::ListIds(index) => {
                let (vid, _) = self.vaults[index];

                let client = ctx.select("/user/client/").expect(line_error!());
                client.try_tell(CMsg::ListAsk(vid), None);
            }
            EMsg::ReturnList(ids) => {
                println!("Read Ids: {:?}", ids);
                ids.iter().for_each(|(id, hint)| {
                    println!("Record Id: {:?}, Hint: {:?}", id, hint);
                });
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
    let external = sys.actor_of::<MockExternalActor>("external").unwrap();

    client.tell(CMsg::SetExternalName(String::from(external_path)), None);
    client.tell(CMsg::CreateVaultAsk, None);

    external.tell(EMsg::CreateVault, None);

    std::thread::sleep(std::time::Duration::from_millis(50));

    external.tell(
        EMsg::WriteData(0, b"Some Data".to_vec(), RecordHint::new(b"").expect(line_error!())),
        None,
    );

    std::thread::sleep(std::time::Duration::from_millis(50));

    external.tell(EMsg::CommitWrite(0), None);

    std::thread::sleep(std::time::Duration::from_millis(50));

    external.tell(EMsg::ListIds(0), None);

    std::thread::sleep(std::time::Duration::from_millis(2000));
    sys.print_tree();
}
