use crate::{
    actors::{BMsg, KMsg, TestMsg},
    ids::{ClientId, VaultId},
    line_error,
    provider::Provider,
};
use std::path::PathBuf;

use engine::vault::{RecordHint, RecordId};

use riker::actors::{Actor, ActorFactory, ActorSelectionFactory, Context, Receive, Sender};

/// Implement Client in external App.
pub struct Client {
    id: ClientId,
    pub external_actor: Option<String>,
}

/// Example of Client Messages.
#[derive(Debug, Clone)]
pub enum ClientMsg {
    SetExternalActorName(String),
    CreateVaultAsk,
    CreateVaultReturn(VaultId, RecordId),
    ReadDataAsk(VaultId, RecordId),
    ReadDataReturn(Vec<u8>),
    WriteData(VaultId, RecordId, Vec<u8>, RecordHint),
    InitRecord(VaultId),
    InitRecordReturn(VaultId, RecordId),
    RevokeData(VaultId, RecordId),
    GarbageCollect(VaultId),
    ListAsk(VaultId),
    ListReturn(Vec<(RecordId, RecordHint)>),
    WriteSnapshot(String, Option<PathBuf>),
    ReadSnapshot(String, Option<PathBuf>),
}

/// Create a new Client.
impl Client {
    pub fn new(id: ClientId, external_actor: Option<String>) -> Self {
        Self { id, external_actor }
    }
}

/// Actor Factor for the Client Struct.
impl ActorFactory for Client {
    fn create() -> Self {
        Client::new(ClientId::random::<Provider>().expect(line_error!()), None)
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
impl Receive<ClientMsg> for Client {
    type Msg = ClientMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, _sender: Sender) {
        match msg {
            // Creates a new Vault in the Bucket using the provided VaultId.
            ClientMsg::CreateVaultAsk => {
                let vid = VaultId::random::<Provider>().expect(line_error!());

                let kstore = ctx.select("/user/keystore/").expect(line_error!());
                kstore.try_tell(KMsg::CreateVault(vid), None);
            }
            // Accepts return statements from the Bucket after CreateVaultAsk is called.
            ClientMsg::CreateVaultReturn(vid, rid) => {
                let external = ctx
                    .select(self.external_actor.as_ref().expect(line_error!()))
                    .expect(line_error!());

                external.try_tell(TestMsg::ReturnCreateVault(vid, rid), None);
            }
            // Asks to read data from the Bucket given a VaultId and a RecordId
            ClientMsg::ReadDataAsk(vid, rid) => {
                let kstore = ctx.select("/user/keystore/").expect(line_error!());
                kstore.try_tell(KMsg::ReadData(vid, rid), None);
            }
            // Deals with the data being returned.
            ClientMsg::ReadDataReturn(data) => {
                let external = ctx
                    .select(self.external_actor.as_ref().expect(line_error!()))
                    .expect(line_error!());

                external.try_tell(TestMsg::ReturnReadData(data), None);
            }
            // Asks to write data into a Record in the associated Vault.  Accepts a VaultId, RecordId, Payload (Vec<u8>) and RecordHint
            ClientMsg::WriteData(vid, rid, payload, hint) => {
                let kstore = ctx.select("/user/keystore/").expect(line_error!());
                kstore.try_tell(KMsg::WriteData(vid, rid, payload, hint), None);
            }
            // Initiates a new Record in a Vault.  Must be called before you can write into a new Record.  Accepts the VaultId
            ClientMsg::InitRecord(vid) => {
                let kstore = ctx.select("/user/keystore/").expect(line_error!());
                kstore.try_tell(KMsg::InitRecord(vid), None);
            }
            // Deals with the aftermath of Initializing a Record.
            ClientMsg::InitRecordReturn(vid, rid) => {
                let external = ctx
                    .select(self.external_actor.as_ref().expect(line_error!()))
                    .expect(line_error!());

                external.try_tell(TestMsg::InitRecordReturn(vid, rid), None);
            }
            // Calls to revoke data from a Vault given a the VaultId and a RecordId
            ClientMsg::RevokeData(vid, rid) => {
                let kstore = ctx.select("/user/keystore/").expect(line_error!());
                kstore.try_tell(KMsg::RevokeData(vid, rid), None);
            }
            // Garbage collects on a vault given the VaultId.
            ClientMsg::GarbageCollect(vid) => {
                let kstore = ctx.select("/user/keystore/").expect(line_error!());
                kstore.try_tell(KMsg::GarbageCollect(vid), None);
            }
            // List all of the RecordIds associated with a Vault given a VaultId.
            ClientMsg::ListAsk(vid) => {
                let kstore = ctx.select("/user/keystore/").expect(line_error!());
                kstore.try_tell(KMsg::ListIds(vid), None);
            }
            // Handle the Returning data from the call to List the RecordIds.
            ClientMsg::ListReturn(ids) => {
                let external = ctx
                    .select(self.external_actor.as_ref().expect(line_error!()))
                    .expect(line_error!());

                external.try_tell(TestMsg::ReturnList(ids), None);
            }
            ClientMsg::SetExternalActorName(id) => {
                self.external_actor = Some(id);
            }
            ClientMsg::WriteSnapshot(pass, path) => {
                let bucket = ctx.select("/user/bucket/").expect(line_error!());
                bucket.try_tell(BMsg::WriteSnapshot::<Provider>(pass, path), None);
            }
            ClientMsg::ReadSnapshot(pass, path) => {
                let bucket = ctx.select("/user/bucket/").expect(line_error!());
                bucket.try_tell(BMsg::ReadSnapshot::<Provider>(pass, path), None);
            }
        }
    }
}
