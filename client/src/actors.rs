use riker::actors::*;

use std::fmt::Debug;

use engine::vault::{BoxProvider, Key, RecordId};

use crate::{
    bucket::{Blob, Bucket},
    client::Client,
    ids::{ClientId, VaultId},
    key_store::KeyStore,
    line_error,
    provider::Provider,
};

#[derive(Debug, Clone)]
pub enum CMsg {
    AddVaultSend,
    CreateRecord(VaultId, Vec<u8>),
    ReadRecord(VaultId, RecordId),
    GarbageCollect(VaultId),
    RevokeRecord(VaultId, RecordId),
    ListRecords(VaultId),
}

#[derive(Debug, Clone)]
pub enum BMsg {
    AddVaultReturn(VaultId),
    CreateRecord(VaultId, Vec<u8>),
    ReadRecord(VaultId, RecordId),
    GarbageCollect(VaultId),
    RevokeRecord(VaultId, RecordId),
    ListRecords(VaultId),
}

#[derive(Clone, Debug)]
pub enum KMsg<P: BoxProvider + Debug> {
    CreateKeySend(VaultId),
    CreateKeyReturn(VaultId, Key<P>),
    GetKeySend(VaultId),
    GetKeyReturn(VaultId, Key<P>),
    UpdateKey(VaultId, Key<P>),
}

impl ActorFactory for Client {
    fn create() -> Self {
        Client::new(ClientId::random::<Provider>().expect(line_error!()))
    }
}

impl ActorFactory for Blob<Provider> {
    fn create() -> Self {
        Blob::new()
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

impl Actor for Blob<Provider> {
    type Msg = BMsg;

    fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        self.receive(ctx, msg, sender);
    }
}

impl Actor for KeyStore<Provider> {
    type Msg = KMsg<Provider>;

    fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        self.receive(ctx, msg, sender);
    }
}

impl Receive<CMsg> for Client {
    type Msg = CMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, _sender: Sender) {}
}

impl Receive<BMsg> for Blob<Provider> {
    type Msg = BMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, _sender: Sender) {}
}

impl Receive<KMsg<Provider>> for KeyStore<Provider> {
    type Msg = KMsg<Provider>;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, _sender: Sender) {}
}
