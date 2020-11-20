use riker::actors::*;

use std::fmt::Debug;

use engine::vault::{BoxProvider, DBView, Key, RecordId};

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
    AddVaultReturn(VaultId),
    CreateRecord(VaultId, Vec<u8>),
    ReadRecord(VaultId, RecordId),
    GarbageCollect(VaultId),
    RevokeRecord(VaultId, RecordId),
    ListRecords(VaultId),
}

#[derive(Debug, Clone)]
pub enum BMsg<P: BoxProvider + Debug> {
    AddVault(VaultId, Key<P>),
    CreateRecord(VaultId, Key<P>, Vec<u8>),
    ReadRecord(VaultId, Key<P>, RecordId),
    GarbageCollect(VaultId),
    RevokeRecord(VaultId, Key<P>, RecordId),
    ListRecords(VaultId),
}

#[derive(Clone, Debug)]
pub enum KMsg {
    AddVault,
    CreateRecord(VaultId, Vec<u8>),
    ReadRecord(VaultId, RecordId),
    GarbageCollect(VaultId),
    RevokeRecord(VaultId, RecordId),
    ListRecords(VaultId),
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
            CMsg::AddVaultSend => {
                let keystore = ctx.select("/user/keystore/").expect(line_error!());
                keystore.try_tell(KMsg::AddVault, None)
            }
            CMsg::AddVaultReturn(vid) => {}
            CMsg::CreateRecord(vid, payload) => {
                let keystore = ctx.select("/user/keystore/").expect(line_error!());
                keystore.try_tell(KMsg::CreateRecord(vid, payload), None)
            }
            CMsg::ReadRecord(vid, tx_id) => {
                let keystore = ctx.select("/user/keystore/").expect(line_error!());
                keystore.try_tell(KMsg::ReadRecord(vid, tx_id), None)
            }
            CMsg::GarbageCollect(vid) => {
                let keystore = ctx.select("/user/keystore/").expect(line_error!());
                keystore.try_tell(KMsg::GarbageCollect(vid), None)
            }

            CMsg::RevokeRecord(vid, tx_id) => {
                let keystore = ctx.select("/user/keystore/").expect(line_error!());
                keystore.try_tell(KMsg::RevokeRecord(vid, tx_id), None)
            }
            CMsg::ListRecords(vid) => {
                let keystore = ctx.select("/user/keystore/").expect(line_error!());
                keystore.try_tell(KMsg::ListRecords(vid), None)
            }
        }
    }
}

impl Receive<BMsg<Provider>> for Blob<Provider> {
    type Msg = BMsg<Provider>;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, _sender: Sender) {
        match msg {
            BMsg::AddVault(vid, key) => {
                self.add_vault(vid, key);
            }
            BMsg::CreateRecord(vid, key, payload) => {}
            BMsg::ReadRecord(vid, key, tx_id) => {}
            BMsg::GarbageCollect(vid) => {}
            BMsg::RevokeRecord(vid, key, tx_id) => {}
            BMsg::ListRecords(vid) => {}
        }
    }
}

impl Receive<KMsg> for KeyStore<Provider> {
    type Msg = KMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, _sender: Sender) {
        match msg {
            KMsg::AddVault => {
                let vid = VaultId::random::<Provider>().expect(line_error!());
                let vid = self.create_key_for_vault(vid);
                let (vid, key) = self.get_key_and_id(vid);

                let keystore = ctx.select("/user/blob/").expect(line_error!());
                keystore.try_tell(BMsg::AddVault(vid, key), None)
            }
            KMsg::CreateRecord(vid, payload) => {}
            KMsg::ReadRecord(vid, tx_id) => {}
            KMsg::GarbageCollect(vid) => {}
            KMsg::RevokeRecord(vid, tx_id) => {}
            KMsg::ListRecords(vid) => {}
        }
    }
}
