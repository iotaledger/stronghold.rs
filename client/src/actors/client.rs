// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    client::{Client, ClientMsg},
    line_error,
    utils::StatusMessage,
    utils::{ClientId, VaultId},
};

use engine::vault::{RecordHint, RecordId};

use riker::actors::*;

use std::{collections::HashMap, path::PathBuf};

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
    Test,
    // Creates a new Vault.
    CreateNewVault,
    // Writes data to a record in the vault.  Accepts the vault id, an optional record id, the payload and the record
    // hint.  If a record id is not specified, the write will default to the head of the vault.  Returns
    // `ReturnCreate`.
    WriteData(VaultId, Option<RecordId>, Vec<u8>, RecordHint),
    // Moves the head forward in the specified Vault and opens a new record.  Returns `ReturnInit`.
    InitRecord(VaultId),
    // Reads data from a record in the vault. Accepts a vault id and an optional record id.  If the record id is not
    // specified, it reads the head.  Returns with `ReturnRead`.
    ReadData(VaultId, Option<RecordId>),
    // Marks a Record for deletion.  Accepts a vault id and a record id.  Deletion only occurs after a
    // `GarbageCollect` is called.
    RevokeData(VaultId, RecordId),
    // Garbages collects any marked records on a Vault. Accepts the vault id.
    GarbageCollect(VaultId),
    // Lists all of the record ids and the record hints for the records in a vault.  Accepts a vault id and returns
    // with `ReturnList`.
    ListIds(VaultId),
    // Writes to the snapshot file.  Accepts the password, an optional filename and an optional filepath.  Defaults to
    // `$HOME/.engine/snapshots/backup.snapshot`.
    WriteSnapshot(Vec<u8>, Option<String>, Option<PathBuf>),
    // Reads from the snapshot file.  Accepts the password, an optional filename and an optional filepath.  Defaults
    // to `$HOME/.engine/snapshots/backup.snapshot`.
    ReadSnapshot(Vec<u8>, Option<String>, Option<PathBuf>),

    ControlRequest(Procedure),
}

/// Messages that come from stronghold
#[derive(Clone, Debug)]
pub enum SHResults {
    ReturnCreateVault(VaultId, RecordId, StatusMessage),
    ReturnWriteData(StatusMessage),
    ReturnInitRecord(VaultId, RecordId, StatusMessage),
    ReturnReadData(Vec<u8>, StatusMessage),
    ReturnRevoke(StatusMessage),
    ReturnGarbage(StatusMessage),
    ReturnList(Vec<(Vec<u8>, RecordHint)>, StatusMessage),
    ReturnWriteSnap(StatusMessage),
    ReturnReadSnap(StatusMessage),
    ReturnControlRequest(ProcResult),
}

impl ActorFactoryArgs<ClientId> for Client {
    fn create_args(client_id: ClientId) -> Self {
        Client::new(client_id)
    }
}

// /// Actor implementation for the Client.
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

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: SHRequest, _sender: Sender) {}
}
