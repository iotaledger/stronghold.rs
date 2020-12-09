// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    actors::{InternalMsg, InternalResults},
    client::{Client, ClientMsg},
    line_error,
    utils::{ClientId, StatusMessage, VaultId},
};

use engine::{
    snapshot,
    vault::{RecordHint, RecordId},
};

use riker::actors::*;

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub enum Procedure {
    SIP10 {
        seed: Vec<u8>,
        vault_path: Vec<u8>,
        record_path: Vec<u8>,
        hint: RecordHint,
    },
}

#[derive(Debug, Clone)]
pub enum ProcResult {
    SIP10 {
        public_key: Vec<u8>,
        vault_path: Vec<u8>,
        record_path: Vec<u8>,
    },
}

#[derive(Clone, Debug)]
pub enum SHRequest {
    // check if vault exists.
    CheckVault(Vec<u8>),
    // check if record exists.
    CheckRecord(Vec<u8>, Option<usize>),

    // Creates a new Vault.
    CreateNewVault(Vec<u8>),

    WriteData(Vec<u8>, Option<usize>, Vec<u8>, RecordHint),
    // Moves the head forward in the specified Vault and opens a new record.  Returns `ReturnInit`.
    InitRecord(Vec<u8>),
    // Reads data from a record in the vault. Accepts a vault id and an optional record id.  If the record id is not
    // specified, it reads the head.  Returns with `ReturnRead`.
    ReadData(Vec<u8>, Option<usize>),
    // Marks a Record for deletion.  Accepts a vault id and a record id.  Deletion only occurs after a
    // `GarbageCollect` is called.
    RevokeData(Vec<u8>, usize),
    // Garbages collects any marked records on a Vault. Accepts the vault id.
    GarbageCollect(Vec<u8>),
    // Lists all of the record ids and the record hints for the records in a vault.  Accepts a vault id and returns
    // with `ReturnList`.
    ListIds(Vec<u8>),
    // Writes to the snapshot file.  Accepts the snapshot key, an optional filename and an optional filepath.
    // Defaults to `$HOME/.engine/snapshots/backup.snapshot`.
    WriteSnapshot(snapshot::Key, Option<String>, Option<PathBuf>),
    // Reads from the snapshot file.  Accepts the snapshot key, an optional filename and an optional filepath.
    // Defaults to `$HOME/.engine/snapshots/backup.snapshot`.
    ReadSnapshot(snapshot::Key, Option<String>, Option<PathBuf>),

    ControlRequest(Procedure),
}

/// Messages that come from stronghold
#[derive(Clone, Debug)]
pub enum SHResults {
    ReturnCreateVault(StatusMessage),
    ReturnWriteData(StatusMessage),
    ReturnInitRecord(usize, StatusMessage),
    ReturnReadData(Vec<u8>, StatusMessage),
    ReturnRevoke(StatusMessage),
    ReturnGarbage(StatusMessage),
    ReturnList(Vec<(Vec<u8>, RecordHint)>, StatusMessage),
    ReturnWriteSnap(StatusMessage),
    ReturnReadSnap(StatusMessage),
    ReturnControlRequest(ProcResult),
    ReturnExistsVault(bool, StatusMessage),
    ReturnExistsRecord(bool, StatusMessage),
}

impl ActorFactoryArgs<ClientId> for Client {
    fn create_args(client_id: ClientId) -> Self {
        Client::new(client_id)
    }
}

/// Actor implementation for the Client.
impl Actor for Client {
    type Msg = ClientMsg;

    fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        self.receive(ctx, msg, sender);
    }
}

impl Receive<SHResults> for Client {
    type Msg = ClientMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: SHResults, _sender: Sender) {}
}

impl Receive<SHRequest> for Client {
    type Msg = ClientMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: SHRequest, sender: Sender) {
        match msg {
            SHRequest::CheckVault(vpath) => {
                let vid = self.derive_vault_id(vpath);
                if self.vault_exist(vid) {
                    sender
                        .as_ref()
                        .expect(line_error!())
                        .try_tell(SHResults::ReturnExistsVault(true, StatusMessage::Ok), None)
                        .expect(line_error!());
                } else {
                    sender
                        .as_ref()
                        .expect(line_error!())
                        .try_tell(SHResults::ReturnExistsVault(false, StatusMessage::Ok), None)
                        .expect(line_error!());
                }
            }
            SHRequest::CheckRecord(vpath, ctr) => {
                let vid = self.derive_vault_id(vpath);
                let rid = self.derive_record_id(vid, ctr);

                let res = self.record_exists_in_vault(vid, rid);
                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnExistsRecord(res, StatusMessage::Ok), None)
                    .expect(line_error!());
            }
            SHRequest::CreateNewVault(vpath) => {
                let vid = self.derive_vault_id(vpath);
                let rid = self.derive_record_id(vid, None);
                let client_str = self.get_client_str();

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::CreateVault(vid, rid), sender);
            }
            SHRequest::WriteData(vpath, idx, data, hint) => {
                let vid = self.derive_vault_id(vpath);
                let rid = self.derive_record_id(vid, idx);
                let client_str = self.get_client_str();

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::WriteData(vid, rid, data, hint), sender);
            }
            SHRequest::InitRecord(vpath) => {
                let vid = self.derive_vault_id(vpath);
                let rid = self.derive_record_id(vid, None);

                let client_str = self.get_client_str();

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::InitRecord(vid, rid), sender);
            }
            SHRequest::ReadData(vpath, idx) => {
                let vid = self.derive_vault_id(vpath);
                let rid = self.derive_record_id(vid, idx);

                println!("{:?}", rid);

                let client_str = self.get_client_str();

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::ReadData(vid, rid), sender);
            }
            SHRequest::RevokeData(vpath, idx) => {}
            SHRequest::GarbageCollect(vpath) => {}
            SHRequest::ListIds(vpath) => {}
            SHRequest::WriteSnapshot(data, name, path) => {}
            SHRequest::ReadSnapshot(data, name, path) => {}
            SHRequest::ControlRequest(procedure) => {}
        }
    }
}

impl Receive<InternalResults> for Client {
    type Msg = ClientMsg;

    fn receive(&mut self, _ctx: &Context<Self::Msg>, msg: InternalResults, sender: Sender) {
        match msg {
            InternalResults::ReturnCreateVault(vid, rid, status) => {
                self.add_vault(vid, rid);

                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnCreateVault(status), None)
                    .expect(line_error!());
            }
            InternalResults::ReturnInitRecord(vid, rid, status) => {
                self.insert_record(vid, rid);

                let ctr = self.get_record_index(vid);

                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnInitRecord(ctr, status), None)
                    .expect(line_error!());
            }
            InternalResults::ReturnReadData(payload, status) => {
                println!("{:?}", payload);
                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnReadData(payload, status), None)
                    .expect(line_error!());
            }
            InternalResults::ReturnList(list, status) => {}
            InternalResults::RebuildCache(vids, rids, status) => {
                self.clear_cache();
                // self.rebuild_cache(vids.clone(), rids.clone());
            }
            InternalResults::ReturnWriteData(status) => {
                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnCreateVault(StatusMessage::Ok), None)
                    .expect(line_error!());
            }
            InternalResults::ReturnRevoke(_) => {}
            InternalResults::ReturnGarbage(_) => {}
            InternalResults::ReturnWriteSnap(_) => {}
            InternalResults::ReturnReadSnap(_) => {}
            InternalResults::ReturnControlRequest(_) => {}
        }
    }
}
