// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    actors::{InternalMsg, InternalResults},
    client::{Client, ClientMsg},
    line_error,
    utils::{Chain, ClientId, ResultMessage, StatusMessage},
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

#[derive(Debug, Clone)]
pub enum SLIP10DeriveInput {
    /// Note that BIP39 seeds are allowed to be used as SLIP10 seeds
    Seed {
        vault_path: Vec<u8>,
    },
    Key {
        vault_path: Vec<u8>,
    },
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum Procedure {
    /// Generate a raw SLIP10 seed and store it in `vault_path`
    ///
    /// Note that this does not generate a BIP39 mnemonic sentence and it's not possible to
    /// generate one: use `BIP39Generate` if a mnemonic sentence will be required.
    SLIP10Generate { vault_path: Vec<u8>, hint: RecordHint },
    /// Derive a SLIP10 child key from a seed or a parent key and store it in `vault_path`
    SLIP10Derive {
        chain: Chain,
        input: SLIP10DeriveInput,
        vault_path: Vec<u8>,
        hint: RecordHint,
    },
    /// Use a BIP39 mnemonic sentence (optionally protected by a passphrase) to create or recover
    /// a BIP39 seed and store it in `vault_path`
    BIP39Recover {
        mnemonic: String,
        passphrase: Option<String>,
        vault_path: Vec<u8>,
        hint: RecordHint,
    },
    /// Generate a BIP39 seed and its corresponding mnemonic sentence (optionally protected by a
    /// passphrase) and store them in `vault_path`
    BIP39Generate {
        passphrase: Option<String>,
        vault_path: Vec<u8>,
        hint: RecordHint,
    },
    /// Read a BIP39 seed and its corresponding mnemonic sentence (optionally protected by a
    /// passphrase) and store them in `vault_path`
    BIP39MnemonicSentence { vault_path: Vec<u8> },
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum ProcResult {
    SLIP10Generate { status: StatusMessage },
    SLIP10Derive { status: StatusMessage },
    BIP39Recover { status: StatusMessage },
    BIP39Generate { status: StatusMessage },
    BIP39MnemonicSentence { result: ResultMessage<String> },
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

    fn receive(&mut self, _ctx: &Context<Self::Msg>, _msg: SHResults, _sender: Sender) {}
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
                let vid = self.derive_vault_id(vpath.clone());
                let rid = self.derive_record_id(vpath, ctr);

                let res = self.record_exists_in_vault(vid, rid);
                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnExistsRecord(res), None)
                    .expect(line_error!());
            }
            SHRequest::CreateNewVault(vpath) => {
                let vid = self.derive_vault_id(vpath.clone());
                let rid = self.derive_record_id(vpath, None);
                let client_str = self.get_client_str();

                self.add_vault_insert_record(vid, rid);

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::CreateVault(vid, rid), sender);
            }
            SHRequest::WriteData(vpath, idx, data, hint) => {
                let vid = self.derive_vault_id(vpath.clone());

                let rid = if let Some(idx) = idx {
                    self.derive_record_id(vpath, Some(idx))
                } else {
                    let ctr = self.get_counter(vid);
                    self.derive_record_id(vpath, Some(ctr - 1))
                };

                let client_str = self.get_client_str();

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::WriteData(vid, rid, data, hint), sender);
            }
            SHRequest::InitRecord(vpath) => {
                let vid = self.derive_vault_id(vpath.clone());
                let rid = self.derive_record_id(vpath, None);

                let client_str = self.get_client_str();

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::InitRecord(vid, rid), sender);
            }
            SHRequest::ReadData(vpath, idx) => {
                let vid = self.derive_vault_id(vpath.clone());

                let rid = if let Some(idx) = idx {
                    self.derive_record_id(vpath, Some(idx))
                } else {
                    let ctr = self.get_counter(vid);

                    self.derive_record_id(vpath, Some(ctr - 1))
                };

                let client_str = self.get_client_str();

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::ReadData(vid, rid), sender);
            }
            SHRequest::RevokeData(vpath, idx) => {
                let vid = self.derive_vault_id(vpath.clone());
                let rid = self.derive_record_id(vpath, Some(idx));

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
                let vid = self.derive_vault_id(vpath.clone());

                let client_str = self.get_client_str();

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::ListIds(vpath, vid), sender);
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
                        let vid = self.derive_vault_id(vault_path.clone());

                        let rid = self.derive_record_id(vault_path, None);

                        if !self.vault_exist(vid) {
                            self.add_vault_insert_record(vid, rid);
                        }

                        internal.try_tell(
                            InternalMsg::SLIP10Generate {
                                vault_id: vid,
                                record_id: rid,
                                hint,
                            },
                            sender,
                        )
                    }
                    Procedure::SLIP10Derive {
                        chain,
                        input:
                            SLIP10DeriveInput::Seed {
                                vault_path: seed_vault_path,
                            },
                        vault_path: key_vault_path,
                        hint,
                    } => {
                        let seed_vault_id = self.derive_vault_id(seed_vault_path.clone());
                        if !self.vault_exist(seed_vault_id) {
                            sender
                                .as_ref()
                                .expect(line_error!())
                                .try_tell(
                                    SHResults::ReturnControlRequest(ProcResult::SLIP10Derive {
                                        status: StatusMessage::Error(
                                            "Failed to find seed vault. Please generate one".into(),
                                        ),
                                    }),
                                    None,
                                )
                                .expect(line_error!());
                            return;
                        }

                        let key_vault_id = self.derive_vault_id(key_vault_path.clone());
                        if !self.vault_exist(key_vault_id) {
                            sender
                                .as_ref()
                                .expect(line_error!())
                                .try_tell(
                                    SHResults::ReturnControlRequest(ProcResult::SLIP10Derive {
                                        status: StatusMessage::Error(
                                            "Failed to find key vault. Please generate one".into(),
                                        ),
                                    }),
                                    None,
                                )
                                .expect(line_error!());
                            return;
                        }

                        let seed_record_id = self.derive_record_id(seed_vault_path.clone(), Some(0));
                        let key_record_id = self.derive_record_id(key_vault_path.clone(), Some(0));

                        internal.try_tell(
                            InternalMsg::SLIP10Derive {
                                chain,
                                seed_vault_id,
                                seed_record_id,
                                key_vault_id,
                                key_record_id,
                                hint,
                            },
                            sender,
                        )
                    }
                    Procedure::BIP39Recover {
                        mnemonic,
                        passphrase,
                        vault_path,
                        hint,
                    } => {
                        let vid = self.derive_vault_id(vault_path.clone());
                        let rid = self.derive_record_id(vault_path, None);

                        if !self.vault_exist(vid) {
                            self.add_vault_insert_record(vid, rid);
                        }

                        internal.try_tell(
                            InternalMsg::BIP39Recover {
                                mnemonic,
                                passphrase: passphrase.unwrap_or_else(|| "".into()),
                                vault_id: vid,
                                record_id: rid,
                                hint,
                            },
                            sender,
                        )
                    }
                    p => sender
                        .as_ref()
                        .expect(line_error!())
                        .try_tell(
                            SHResults::ReturnControlRequest(ProcResult::SLIP10Derive {
                                status: StatusMessage::Error(format!("procedure not implemented: {:?}", p)),
                            }),
                            None,
                        )
                        .expect(line_error!()),
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

                let ctr = self.get_counter(vid);

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
            InternalResults::ReturnList(vpath, list, status) => {
                let ids: Vec<(usize, RecordHint)> = list
                    .into_iter()
                    .map(|(rid, hint)| {
                        let idx = self.get_index_from_record_id(vpath.clone(), rid);
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

                self.rebuild_cache(vids, rids);

                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnReadSnap(status), None)
                    .expect(line_error!());
            }
            InternalResults::ReturnWriteData(_status) => {
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
