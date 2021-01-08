// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    actors::{InternalMsg, InternalResults},
    client::{Client, ClientMsg, ReadWrite},
    line_error,
    utils::{hd, ClientId, ResultMessage, StatusMessage},
    Location,
};

use engine::{snapshot, vault::RecordHint};

use riker::actors::*;

use std::{path::PathBuf, time::Duration};

/// `SLIP10DeriveInput` type used to specify a Seed location or a Key location for the `SLIP10Derive` procedure.
#[derive(Debug, Clone)]
pub enum SLIP10DeriveInput {
    /// Note that BIP39 seeds are allowed to be used as SLIP10 seeds
    Seed(Location),
    Key(Location),
}

/// Procedure type used to call to the runtime via `Strongnhold.runtime_exec(...)`.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum Procedure {
    /// Generate a raw SLIP10 seed of the specified size and store it in the `output` location
    ///
    /// Note that this does not generate a BIP39 mnemonic sentence and it's not possible to
    /// generate one: use `BIP39Generate` if a mnemonic sentence will be required.
    SLIP10Generate {
        output: Location,
        hint: RecordHint,
        size_bytes: usize,
    },
    /// Derive a SLIP10 child key from a seed or a parent key and store it in output location
    SLIP10Derive {
        chain: hd::Chain,
        input: SLIP10DeriveInput,
        output: Location,
        hint: RecordHint,
    },
    /// Use a BIP39 mnemonic sentence (optionally protected by a passphrase) to create or recover
    /// a BIP39 seed and store it in the `output` location
    BIP39Recover {
        mnemonic: String,
        passphrase: Option<String>,
        output: Location,
        hint: RecordHint,
    },
    /// Generate a BIP39 seed and its corresponding mnemonic sentence (optionally protected by a
    /// passphrase) and store them in the `output` location
    BIP39Generate {
        passphrase: Option<String>,
        output: Location,
        hint: RecordHint,
    },
    /// Read a BIP39 seed and its corresponding mnemonic sentence (optionally protected by a
    /// passphrase) and store them in the `output` location
    BIP39MnemonicSentence { seed: Location },
    /// Derive an Ed25519 public key from the corresponding private key stored at the specified
    /// location
    Ed25519PublicKey { private_key: Location },
    /// Use the specified Ed25519 compatible key to sign the given message
    ///
    /// Compatible keys are any record that contain the desired key material in the first 32 bytes,
    /// in particular SLIP10 keys are compatible.
    Ed25519Sign { private_key: Location, msg: Vec<u8> },
    /// Derive an Ed25519 key using SLIP10 from the specified path and derive its public key
    SLIP10DeriveAndEd25519PublicKey { path: String, seed: Location },
    /// Derive an Ed25519 key using SLIP10 from the specified path and seed and use it to sign the given message
    SLIP10DeriveAndEd25519Sign { path: String, seed: Location, msg: Vec<u8> },
    /// Derive a SLIP10 key from a SLIP10/BIP39 seed using path, sign the essence using Ed25519, return the signature
    /// and the corresponding public key
    ///
    /// This is equivalent to separate calls to SLIP10Derive, Ed25519PublicKey, and Ed25519Sign but
    /// does not store the derived key.
    SignUnlockBlock {
        seed: Location,
        path: String,
        essence: Vec<u8>,
    },
}

/// A Procedure return result type.  Contains the different return values for the `Procedure` type calls used with
/// `Stronghold.runtime_exec(...)`.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum ProcResult {
    /// Return from generating a `SLIP10` seed.
    SLIP10Generate(StatusMessage),
    /// Returns the public key derived from the `SLIP10Derive` call.
    SLIP10Derive(StatusMessage),
    /// `BIP39Recover` return value.
    BIP39Recover(StatusMessage),
    /// `BIP39Generate` return value.
    BIP39Generate(StatusMessage),
    /// `BIP39MnemonicSentence` return value. Returns the mnemonic sentence for the corresponding seed.
    BIP39MnemonicSentence(ResultMessage<String>),
    /// Return value for `Ed25519PublicKey`. Returns an Ed25519 public key.
    Ed25519PublicKey(ResultMessage<[u8; crypto::ed25519::COMPRESSED_PUBLIC_KEY_LENGTH]>),
    /// Return value for `SLIP10DeriveAndEd25519PublicKey`. Returns an Ed25519 public key.
    SLIP10DeriveAndEd25519PublicKey(ResultMessage<[u8; crypto::ed25519::COMPRESSED_PUBLIC_KEY_LENGTH]>),
    /// Return value for `Ed25519Sign`. Returns an Ed25519 signature.
    Ed25519Sign(ResultMessage<[u8; crypto::ed25519::SIGNATURE_LENGTH]>),
    /// Return value for `SLIP10DeriveAndEd25519Sign`. Returns an Ed25519 signature.
    SLIP10DeriveAndEd25519Sign(ResultMessage<[u8; crypto::ed25519::SIGNATURE_LENGTH]>),
    /// Return value for `SignUnlockBlock`. Returns a Ed25519 signature and a Ed25519 public key.
    SignUnlockBlock(
        ResultMessage<(
            [u8; crypto::ed25519::SIGNATURE_LENGTH],
            [u8; crypto::ed25519::COMPRESSED_PUBLIC_KEY_LENGTH],
        )>,
    ),
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub enum SHRequest {
    // check if vault exists.
    CheckVault(Vec<u8>),
    // check if record exists.
    CheckRecord {
        location: Location,
    },
    WriteToStore {
        location: Location,
        payload: Vec<u8>,
        lifetime: Option<Duration>,
    },
    ReadFromStore {
        location: Location,
    },

    // Creates a new Vault.
    CreateNewVault(Location),

    WriteToVault {
        location: Location,
        payload: Vec<u8>,
        hint: RecordHint,
    },
    // Moves the head forward in the specified Vault and opens a new record.  Returns `ReturnInit`.
    InitRecord {
        location: Location,
    },
    // Reads data from a record in the vault. Accepts a vault id and an optional record id.  If the record id is not
    // specified, it reads the head.  Returns with `ReturnRead`.
    #[cfg(test)]
    ReadFromVault {
        location: Location,
    },
    // Marks a Record for deletion.  Accepts a vault id and a record id.  Deletion only occurs after a
    // `GarbageCollect` is called.
    RevokeData {
        location: Location,
    },
    // Garbages collects any marked records on a Vault. Accepts the vault id.
    GarbageCollect(Vec<u8>),
    // Lists all of the record ids and the record hints for the records in a vault.  Accepts a vault id and returns
    // with `ReturnList`.
    ListIds(Vec<u8>),

    // Reads from the snapshot file.  Accepts the snapshot key, an optional filename and an optional filepath.
    // Defaults to `$HOME/.engine/snapshots/backup.snapshot`.
    ReadSnapshot {
        key: snapshot::Key,
        filename: Option<String>,
        path: Option<PathBuf>,
        cid: ClientId,
        former_cid: Option<ClientId>,
    },

    WriteSnapshotAll {
        key: snapshot::Key,
        filename: Option<String>,
        path: Option<PathBuf>,
        is_final: bool,
    },

    ClearCache,

    ControlRequest(Procedure),
}

/// Messages that come from stronghold
#[derive(Clone, Debug)]
pub enum SHResults {
    ReturnWriteStore(StatusMessage),
    ReturnReadStore(Vec<u8>, StatusMessage),
    ReturnCreateVault(StatusMessage),
    ReturnWriteVault(StatusMessage),
    ReturnInitRecord(StatusMessage),
    ReturnReadVault(Vec<u8>, StatusMessage),
    ReturnRevoke(StatusMessage),
    ReturnGarbage(StatusMessage),
    ReturnList(Vec<(usize, RecordHint)>, StatusMessage),
    ReturnWriteSnap(StatusMessage),
    ReturnReadSnap(StatusMessage),
    ReturnClearCache(StatusMessage),
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
        macro_rules! ensure_vault_exists {
            ( $x:expr, $V:tt, $k:expr ) => {
                if !self.vault_exist($x) {
                    sender
                        .as_ref()
                        .expect(line_error!())
                        .try_tell(
                            SHResults::ReturnControlRequest(ProcResult::$V(ResultMessage::Error(format!(
                                "Failed to find {} vault. Please generate one",
                                $k
                            )))),
                            None,
                        )
                        .expect(line_error!());
                    return;
                }
            };
        }

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
            SHRequest::CheckRecord { location } => {
                let (vid, rid) = self.resolve_location(location, ReadWrite::Write);

                let res = self.record_exists_in_vault(vid, rid);
                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnExistsRecord(res), None)
                    .expect(line_error!());
            }
            SHRequest::CreateNewVault(location) => {
                let (vid, rid) = self.resolve_location(location, ReadWrite::Write);
                let client_str = self.get_client_str();

                self.add_new_vault(vid);
                self.add_record_to_vault(vid, rid);

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::CreateVault(vid, rid), sender);
            }
            SHRequest::WriteToVault {
                location,
                payload,
                hint,
            } => {
                let (vid, rid) = self.resolve_location(location, ReadWrite::Write);

                let client_str = self.get_client_str();

                self.increment_counter(vid);

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::WriteToVault(vid, rid, payload, hint), sender);
            }
            SHRequest::InitRecord { location } => {
                let (vid, rid) = self.resolve_location(location, ReadWrite::Write);

                let client_str = self.get_client_str();

                self.add_record_to_vault(vid, rid);

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::InitRecord(vid, rid), sender);
            }
            #[cfg(test)]
            SHRequest::ReadFromVault { location } => {
                let (vid, rid) = self.resolve_location(location, ReadWrite::Read);

                let client_str = self.get_client_str();

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::ReadFromVault(vid, rid), sender);
            }
            SHRequest::RevokeData { location } => {
                let (vid, rid) = self.resolve_location(location, ReadWrite::Read);

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
                let vid = self.derive_vault_id(&vpath);

                let client_str = self.get_client_str();

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::ListIds(vpath, vid), sender);
            }

            SHRequest::ReadSnapshot {
                key,
                filename,
                path,
                cid,
                former_cid,
            } => {
                let client_str = self.get_client_str();

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::ReadSnapshot(key, filename, path, cid, former_cid), sender);
            }
            SHRequest::ClearCache => {
                self.clear_cache();

                let client_str = self.get_client_str();

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::ClearCache, sender);
            }
            SHRequest::WriteSnapshotAll {
                key,
                filename,
                path,
                is_final,
            } => {
                let client_str = self.get_client_str();

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(
                    InternalMsg::WriteSnapshotAll {
                        key,
                        path,
                        filename,
                        id: self.client_id,
                        data: self.clone(),
                        is_final,
                    },
                    sender,
                )
            }
            SHRequest::WriteToStore {
                location,
                payload,
                lifetime,
            } => {
                let client_str = self.get_client_str();

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                let (vid, _) = self.resolve_location(location, ReadWrite::Write);

                internal.try_tell(
                    InternalMsg::WriteToStore {
                        key: vid,
                        payload,
                        lifetime,
                    },
                    sender,
                )
            }
            SHRequest::ReadFromStore { location } => {
                let client_str = self.get_client_str();

                let (vid, _) = self.resolve_location(location, ReadWrite::Read);

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::ReadFromStore { key: vid }, sender)
            }
            SHRequest::ControlRequest(procedure) => {
                let client_str = self.get_client_str();

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                match procedure {
                    Procedure::SLIP10Generate {
                        output,
                        hint,
                        size_bytes,
                    } => {
                        let (vid, rid) = self.resolve_location(output, ReadWrite::Write);

                        if !self.vault_exist(vid) {
                            self.add_new_vault(vid);
                            self.add_record_to_vault(vid, rid);
                            self.increment_counter(vid);
                        } else {
                            self.add_record_to_vault(vid, rid);
                            self.increment_counter(vid);
                        }

                        internal.try_tell(
                            InternalMsg::SLIP10Generate {
                                vault_id: vid,
                                record_id: rid,
                                hint,
                                size_bytes,
                            },
                            sender,
                        )
                    }
                    Procedure::SLIP10Derive {
                        chain,
                        input: SLIP10DeriveInput::Seed(seed),
                        output,
                        hint,
                    } => {
                        let (seed_vault_id, seed_record_id) = self.resolve_location(seed, ReadWrite::Write);
                        ensure_vault_exists!(seed_vault_id, SLIP10Derive, "seed");

                        let (key_vault_id, key_record_id) = self.resolve_location(output, ReadWrite::Write);

                        if !self.vault_exist(key_vault_id) {
                            self.add_new_vault(key_vault_id);
                            self.add_record_to_vault(key_vault_id, key_record_id);
                            self.increment_counter(key_vault_id);
                        } else {
                            self.add_record_to_vault(key_vault_id, key_record_id);
                            self.increment_counter(key_vault_id);
                        }

                        internal.try_tell(
                            InternalMsg::SLIP10DeriveFromSeed {
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
                    Procedure::SLIP10Derive {
                        chain,
                        input: SLIP10DeriveInput::Key(parent),
                        output,
                        hint,
                    } => {
                        let (parent_vault_id, parent_record_id) = self.resolve_location(parent, ReadWrite::Read);
                        ensure_vault_exists!(parent_vault_id, SLIP10Derive, "parent key");

                        let (child_vault_id, child_record_id) = self.resolve_location(output, ReadWrite::Write);

                        if !self.vault_exist(child_vault_id) {
                            self.add_new_vault(child_vault_id);
                            self.add_record_to_vault(child_vault_id, child_record_id);
                            self.increment_counter(child_vault_id);
                        } else {
                            self.add_record_to_vault(child_vault_id, child_record_id);
                            self.increment_counter(child_vault_id);
                        }

                        internal.try_tell(
                            InternalMsg::SLIP10DeriveFromKey {
                                chain,
                                parent_vault_id,
                                parent_record_id,
                                child_vault_id,
                                child_record_id,
                                hint,
                            },
                            sender,
                        )
                    }
                    Procedure::BIP39Generate {
                        passphrase,
                        output,
                        hint,
                    } => {
                        let (vault_id, record_id) = self.resolve_location(output, ReadWrite::Read);

                        if !self.vault_exist(vault_id) {
                            self.add_new_vault(vault_id);
                            self.add_record_to_vault(vault_id, record_id);
                            self.increment_counter(vault_id);
                        } else {
                            self.add_record_to_vault(vault_id, record_id);
                            self.increment_counter(vault_id);
                        }

                        internal.try_tell(
                            InternalMsg::BIP39Generate {
                                passphrase: passphrase.unwrap_or_else(|| "".into()),
                                vault_id,
                                record_id,
                                hint,
                            },
                            sender,
                        )
                    }
                    Procedure::BIP39Recover {
                        mnemonic,
                        passphrase,
                        output,
                        hint,
                    } => {
                        let (vault_id, record_id) = self.resolve_location(output, ReadWrite::Write);

                        if !self.vault_exist(vault_id) {
                            self.add_new_vault(vault_id);
                            self.add_record_to_vault(vault_id, record_id);
                            self.increment_counter(vault_id);
                        } else {
                            self.add_record_to_vault(vault_id, record_id);
                            self.increment_counter(vault_id);
                        }

                        internal.try_tell(
                            InternalMsg::BIP39Recover {
                                mnemonic,
                                passphrase: passphrase.unwrap_or_else(|| "".into()),
                                vault_id,
                                record_id,
                                hint,
                            },
                            sender,
                        )
                    }
                    Procedure::BIP39MnemonicSentence { .. } => todo!(),
                    Procedure::Ed25519PublicKey { private_key } => {
                        let (vault_id, record_id) = self.resolve_location(private_key, ReadWrite::Read);
                        internal.try_tell(InternalMsg::Ed25519PublicKey { vault_id, record_id }, sender)
                    }
                    Procedure::SLIP10DeriveAndEd25519PublicKey { path, seed } => {
                        let (vault_id, record_id) = self.resolve_location(seed, ReadWrite::Read);
                        internal.try_tell(
                            InternalMsg::SLIP10DeriveAndEd25519PublicKey {
                                path,
                                vault_id,
                                record_id,
                            },
                            sender,
                        )
                    }
                    Procedure::Ed25519Sign { private_key, msg } => {
                        let (vault_id, record_id) = self.resolve_location(private_key, ReadWrite::Read);
                        internal.try_tell(
                            InternalMsg::Ed25519Sign {
                                vault_id,
                                record_id,
                                msg,
                            },
                            sender,
                        )
                    }
                    Procedure::SLIP10DeriveAndEd25519Sign { path, seed, msg } => {
                        let (vault_id, record_id) = self.resolve_location(seed, ReadWrite::Read);
                        internal.try_tell(
                            InternalMsg::SLIP10DeriveAndEd25519Sign {
                                path,
                                vault_id,
                                record_id,
                                msg,
                            },
                            sender,
                        )
                    }
                    Procedure::SignUnlockBlock { seed, path, essence } => {
                        let (vault_id, record_id) = self.resolve_location(seed, ReadWrite::Read);
                        internal.try_tell(
                            InternalMsg::SignUnlockBlock {
                                vault_id,
                                record_id,
                                path,
                                essence,
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
            InternalResults::ReturnInitRecord(status) => {
                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnInitRecord(status), None)
                    .expect(line_error!());
            }
            InternalResults::ReturnReadVault(payload, status) => {
                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnReadVault(payload, status), None)
                    .expect(line_error!());
            }
            InternalResults::ReturnList(vpath, list, status) => {
                let ids: Vec<(usize, RecordHint)> = list
                    .into_iter()
                    .map(|(rid, hint)| {
                        let idx = self.get_index_from_record_id(&vpath, rid);
                        (idx, hint)
                    })
                    .collect();

                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnList(ids, status), None)
                    .expect(line_error!());
            }
            InternalResults::RebuildCache(state, status) => {
                self.clear_cache();

                self.rebuild_cache(state);

                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnReadSnap(status), None)
                    .expect(line_error!());
            }
            InternalResults::ReturnWriteVault(status) => {
                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnWriteVault(status), None)
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
            InternalResults::ReturnClearCache(status) => {
                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnClearCache(status), None)
                    .expect(line_error!());
            }
            InternalResults::ReturnWriteStore(status) => {
                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnWriteStore(status), None)
                    .expect(line_error!());
            }
            InternalResults::ReturnReadStore(payload, status) => {
                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnReadStore(payload, status), None)
                    .expect(line_error!());
            }
        }
    }
}
