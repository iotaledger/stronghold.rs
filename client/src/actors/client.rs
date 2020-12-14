// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    actors::{InternalMsg, InternalResults},
    client::{Client, ClientMsg},
    line_error,
    utils::{Chain, ClientId, StatusMessage},
};

use engine::{snapshot, vault::RecordHint};

use riker::actors::*;

use std::path::PathBuf;

/// TODO: Bip39: words -> seed
/// TODO: SLIP10: seed -> public key
/// TODO: SLIP10: add argument for subtree.
/// TODO: Ed25519 SIGN method.
/// TODO: Add feature flags
/// GENERATE SLIP10 SEED -> Sticks seed in vault -> return chaincode
/// GENERATE BIP39 words -> generates entropy then creates words and the slip10 seed (optionally store entropy).
/// DERIVE SLIP10 Key
/// Recover BIP39 SEED -> words checks seed against seed in vault.
/// backup Words -> returns words

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum Procedure {
    SLIP10Generate {
        vault_path: Vec<u8>,
        hint: RecordHint,
    },
    SLIP10Step {
        chain: Chain,
        seed_vault_path: Vec<u8>,
        hint: RecordHint,
    },
    BIP32 {
        mnemonic: String,
        passphrase: String,
        vault_path: Vec<u8>,
        hint: RecordHint,
    },
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum ProcResult {
    SLIP10Generate { status: StatusMessage },
    SLIP10Step { status: StatusMessage },
    BIP32 { status: StatusMessage },
}

#[allow(dead_code)]
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
    ReturnList(Vec<(usize, RecordHint)>, StatusMessage),
    ReturnWriteSnap(StatusMessage),
    ReturnReadSnap(StatusMessage),

    ReturnControlRequest(ProcResult),
    ReturnExistsVault(bool),
    ReturnExistsRecord(bool),
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

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: SHResults, _sender: Sender) {
        println!("{:?}", msg);
    }
}

impl Receive<SHRequest> for Client {
    type Msg = ClientMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: SHRequest, sender: Sender) {
        match msg {
            SHRequest::CheckVault(vpath) => {
                let vid = self.derive_vault_id(vpath);
                let res = self.vault_exist(vid);

                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnExistsVault(res), None)
                    .expect(line_error!());
            }
            SHRequest::CheckRecord(vpath, ctr) => {
                let vid = self.derive_vault_id(vpath);
                let rid = self.derive_record_id(vid, ctr);

                let res = self.record_exists_in_vault(vid, rid);
                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnExistsRecord(res), None)
                    .expect(line_error!());
            }
            SHRequest::CreateNewVault(vpath) => {
                let vid = self.derive_vault_id(vpath);
                let rid = self.derive_record_id(vid, None);
                let client_str = self.get_client_str();

                self.add_vault_insert_record(vid, rid);

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::CreateVault(vid, rid), sender);
            }
            SHRequest::WriteData(vpath, idx, data, hint) => {
                let vid = self.derive_vault_id(vpath);

                let rid = if let Some(idx) = idx {
                    self.derive_record_id(vid, Some(idx))
                } else {
                    let ctr = self.get_counter_index(vid);
                    self.derive_record_id(vid, Some(ctr - 1))
                };

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

                let rid = if let Some(idx) = idx {
                    self.derive_record_id(vid, Some(idx))
                } else {
                    let ctr = self.get_counter_index(vid);

                    self.derive_record_id(vid, Some(ctr - 1))
                };

                let client_str = self.get_client_str();

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::ReadData(vid, rid), sender);
            }
            SHRequest::RevokeData(vpath, idx) => {
                let vid = self.derive_vault_id(vpath);
                let rid = self.derive_record_id(vid, Some(idx));

                let client_str = self.get_client_str();

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::RevokeData(vid, rid), sender);
            }
            SHRequest::GarbageCollect(vpath) => {
                let vid = self.derive_vault_id(vpath);

                let client_str = self.get_client_str();

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::GarbageCollect(vid), sender);
            }
            SHRequest::ListIds(vpath) => {
                let vid = self.derive_vault_id(vpath);

                let client_str = self.get_client_str();

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::ListIds(vid), sender);
            }
            SHRequest::WriteSnapshot(data, name, path) => {
                let client_str = self.get_client_str();

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::WriteSnapshot(data, name, path, client_str), sender);
            }
            SHRequest::ReadSnapshot(data, name, path) => {
                let client_str = self.get_client_str();

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::ReadSnapshot(data, name, path, client_str), sender);
            }
            SHRequest::ControlRequest(procedure) => {
                let client_str = self.get_client_str();

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                match procedure {
                    Procedure::SLIP10Generate { vault_path, hint } => {
                        let vid = self.derive_vault_id(vault_path);

                        let rid = self.derive_record_id(vid, None);

                        if !self.vault_exist(vid) {
                            self.add_vault_insert_record(vid, rid);
                        }

                        internal.try_tell(
                            InternalMsg::SLIP10Generate {
                                vault_id: vid,
                                record_id: rid,
                                hint: hint,
                            },
                            sender,
                        )
                    }
                    Procedure::SLIP10Step {
                        chain,
                        seed_vault_path,
                        hint,
                    } => {
                        let vid = self.derive_vault_id(seed_vault_path);
                        if self.vault_exist(vid) {
                            let seed_rid = self.derive_record_id(vid, Some(0));

                            let ctr = self.get_counter_index(vid);

                            let key_rid = self.derive_record_id(vid, Some(ctr));

                            internal.try_tell(
                                InternalMsg::SLIP10Step {
                                    chain: chain,
                                    seed_vault_id: vid,
                                    seed_record_id: seed_rid,
                                    key_record_id: key_rid,
                                    hint: hint,
                                },
                                sender,
                            )
                        } else {
                            sender
                                .as_ref()
                                .expect(line_error!())
                                .try_tell(
                                    SHResults::ReturnControlRequest(ProcResult::SLIP10Step {
                                        status: StatusMessage::Error(
                                            "Failed to find seed vault. Please generate one".into(),
                                        ),
                                    }),
                                    None,
                                )
                                .expect(line_error!());
                        }
                    }
                    Procedure::BIP32 {
                        mnemonic,
                        passphrase,
                        vault_path,
                        hint,
                    } => {
                        let vid = self.derive_vault_id(vault_path);
                        let rid = self.derive_record_id(vid, None);

                        if !self.vault_exist(vid) {
                            self.add_vault_insert_record(vid, rid);
                        }

                        internal.try_tell(
                            InternalMsg::BIP32 {
                                mnemonic: mnemonic,
                                passphrase: passphrase,
                                vault_id: vid,
                                record_id: rid,
                                hint: hint,
                            },
                            sender,
                        )
                    }
                }
            }
        }
    }
}

impl Receive<InternalResults> for Client {
    type Msg = ClientMsg;

    fn receive(&mut self, _ctx: &Context<Self::Msg>, msg: InternalResults, sender: Sender) {
        match msg {
            InternalResults::ReturnCreateVault(status) => {
                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnCreateVault(status), None)
                    .expect(line_error!());
            }
            InternalResults::ReturnInitRecord(vid, rid, status) => {
                self.add_vault_insert_record(vid, rid);

                let ctr = self.get_counter_index(vid);

                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnInitRecord(ctr - 1, status), None)
                    .expect(line_error!());
            }
            InternalResults::ReturnReadData(payload, status) => {
                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnReadData(payload, status), None)
                    .expect(line_error!());
            }
            InternalResults::ReturnList(vid, list, status) => {
                let ids: Vec<(usize, RecordHint)> = list
                    .into_iter()
                    .map(|(rid, hint)| {
                        let idx = self.get_index_from_record_id(vid, rid);
                        (idx, hint)
                    })
                    .collect();

                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnList(ids, status), None)
                    .expect(line_error!());
            }
            InternalResults::RebuildCache(vids, rids, status) => {
                self.clear_cache();

                self.rebuild_cache(vids.clone(), rids.clone());

                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnReadSnap(status), None)
                    .expect(line_error!());
            }
            InternalResults::ReturnWriteData(status) => {
                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnCreateVault(StatusMessage::Ok), None)
                    .expect(line_error!());
            }
            InternalResults::ReturnRevoke(status) => {
                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnRevoke(status), None)
                    .expect(line_error!());
            }
            InternalResults::ReturnGarbage(status) => {
                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnGarbage(status), None)
                    .expect(line_error!());
            }
            InternalResults::ReturnWriteSnap(status) => {
                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnWriteSnap(status), None)
                    .expect(line_error!());
            }

            InternalResults::ReturnControlRequest(result) => {
                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnControlRequest(result), None)
                    .expect(line_error!());
            }
        }
    }
}
