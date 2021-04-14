// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    actors::{InternalMsg, InternalResults, SMsg},
    line_error,
    state::client::{Client, ClientMsg},
    utils::{ResultMessage, StatusMessage},
    Location,
};

use stronghold_utils::GuardDebug;

use crypto::keys::slip10::{Chain, ChainCode};

use engine::{
    snapshot,
    vault::{ClientId, RecordHint, RecordId},
};
use serde::{Deserialize, Serialize};

use riker::actors::*;

use core::{
    array::TryFromSliceError,
    convert::{TryFrom, TryInto},
};
use std::{path::PathBuf, time::Duration};

#[cfg(feature = "communication")]
use communication::actor::{PermissionValue, RequestPermissions, ToPermissionVariants, VariantPermission};

/// `SLIP10DeriveInput` type used to specify a Seed location or a Key location for the `SLIP10Derive` procedure.
#[derive(GuardDebug, Clone, Serialize, Deserialize)]
pub enum SLIP10DeriveInput {
    /// Note that BIP39 seeds are allowed to be used as SLIP10 seeds
    Seed(Location),
    Key(Location),
}

/// Procedure type used to call to the runtime via `Strongnhold.runtime_exec(...)`.
#[allow(dead_code)]
#[derive(GuardDebug, Clone, Serialize, Deserialize)]
pub enum Procedure {
    /// Generate a raw SLIP10 seed of the specified size (in bytes, defaults to 64 bytes/512 bits) and store it in the
    /// `output` location
    ///
    /// Note that this does not generate a BIP39 mnemonic sentence and it's not possible to
    /// generate one: use `BIP39Generate` if a mnemonic sentence will be required.
    SLIP10Generate {
        output: Location,
        hint: RecordHint,
        size_bytes: Option<usize>,
    },
    /// Derive a SLIP10 child key from a seed or a parent key, store it in output location and
    /// return the corresponding chain code
    SLIP10Derive {
        chain: Chain,
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
}

/// A Procedure return result type.  Contains the different return values for the `Procedure` type calls used with
/// `Stronghold.runtime_exec(...)`.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "SerdeProcResult")]
#[serde(into = "SerdeProcResult")]
pub enum ProcResult {
    /// Return from generating a `SLIP10` seed.
    SLIP10Generate(StatusMessage),
    /// Returns the public key derived from the `SLIP10Derive` call.
    SLIP10Derive(ResultMessage<ChainCode>),
    /// `BIP39Recover` return value.
    BIP39Recover(StatusMessage),
    /// `BIP39Generate` return value.
    BIP39Generate(StatusMessage),
    /// `BIP39MnemonicSentence` return value. Returns the mnemonic sentence for the corresponding seed.
    BIP39MnemonicSentence(ResultMessage<String>),
    /// Return value for `Ed25519PublicKey`. Returns an Ed25519 public key.
    Ed25519PublicKey(ResultMessage<[u8; crypto::signatures::ed25519::COMPRESSED_PUBLIC_KEY_LENGTH]>),
    /// Return value for `Ed25519Sign`. Returns an Ed25519 signature.
    Ed25519Sign(ResultMessage<[u8; crypto::signatures::ed25519::SIGNATURE_LENGTH]>),
    /// Generic Error return message.
    Error(String),
}

impl TryFrom<SerdeProcResult> for ProcResult {
    type Error = TryFromSliceError;

    fn try_from(serde_proc_result: SerdeProcResult) -> Result<Self, TryFromSliceError> {
        match serde_proc_result {
            SerdeProcResult::SLIP10Generate(msg) => Ok(ProcResult::SLIP10Generate(msg)),
            SerdeProcResult::SLIP10Derive(msg) => Ok(ProcResult::SLIP10Derive(msg)),
            SerdeProcResult::BIP39Recover(msg) => Ok(ProcResult::BIP39Recover(msg)),
            SerdeProcResult::BIP39Generate(msg) => Ok(ProcResult::BIP39Generate(msg)),
            SerdeProcResult::BIP39MnemonicSentence(msg) => Ok(ProcResult::BIP39MnemonicSentence(msg)),
            SerdeProcResult::Ed25519PublicKey(msg) => {
                let msg: ResultMessage<[u8; crypto::signatures::ed25519::COMPRESSED_PUBLIC_KEY_LENGTH]> = match msg {
                    ResultMessage::Ok(v) => ResultMessage::Ok(v.as_slice().try_into()?),
                    ResultMessage::Error(e) => ResultMessage::Error(e),
                };
                Ok(ProcResult::Ed25519PublicKey(msg))
            }
            SerdeProcResult::Ed25519Sign(msg) => {
                let msg: ResultMessage<[u8; crypto::signatures::ed25519::SIGNATURE_LENGTH]> = match msg {
                    ResultMessage::Ok(v) => ResultMessage::Ok(v.as_slice().try_into()?),
                    ResultMessage::Error(e) => ResultMessage::Error(e),
                };
                Ok(ProcResult::Ed25519Sign(msg))
            }
            SerdeProcResult::Error(err) => Ok(ProcResult::Error(err)),
        }
    }
}

// Replaces arrays in ProcResult with vectors to derive Serialize/ Deserialize
#[derive(Clone, Serialize, Deserialize)]
enum SerdeProcResult {
    SLIP10Generate(StatusMessage),
    SLIP10Derive(ResultMessage<ChainCode>),
    BIP39Recover(StatusMessage),
    BIP39Generate(StatusMessage),
    BIP39MnemonicSentence(ResultMessage<String>),
    Ed25519PublicKey(ResultMessage<Vec<u8>>),
    Ed25519Sign(ResultMessage<Vec<u8>>),
    Error(String),
}

impl From<ProcResult> for SerdeProcResult {
    fn from(proc_result: ProcResult) -> Self {
        match proc_result {
            ProcResult::SLIP10Generate(msg) => SerdeProcResult::SLIP10Generate(msg),
            ProcResult::SLIP10Derive(msg) => SerdeProcResult::SLIP10Derive(msg),
            ProcResult::BIP39Recover(msg) => SerdeProcResult::BIP39Recover(msg),
            ProcResult::BIP39Generate(msg) => SerdeProcResult::BIP39Generate(msg),
            ProcResult::BIP39MnemonicSentence(msg) => SerdeProcResult::BIP39MnemonicSentence(msg),
            ProcResult::Ed25519PublicKey(msg) => {
                let msg = match msg {
                    ResultMessage::Ok(slice) => ResultMessage::Ok(slice.to_vec()),
                    ResultMessage::Error(error) => ResultMessage::Error(error),
                };
                SerdeProcResult::Ed25519PublicKey(msg)
            }
            ProcResult::Ed25519Sign(msg) => {
                let msg = match msg {
                    ResultMessage::Ok(slice) => ResultMessage::Ok(slice.to_vec()),
                    ResultMessage::Error(error) => ResultMessage::Error(error),
                };
                SerdeProcResult::Ed25519Sign(msg)
            }
            ProcResult::Error(err) => SerdeProcResult::Error(err),
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, GuardDebug, Serialize, Deserialize)]
#[cfg_attr(feature = "communication", derive(RequestPermissions))]
pub enum SHRequest {
    // check if vault exists.
    CheckVault(Vec<u8>),
    // check if record exists.
    CheckRecord {
        location: Location,
    },
    // Write to the store.
    WriteToStore {
        location: Location,
        payload: Vec<u8>,
        lifetime: Option<Duration>,
    },
    // Read from the store.
    ReadFromStore {
        location: Location,
    },
    // Delete a key/value pair from the store.
    DeleteFromStore(Location),

    // Creates a new Vault.
    CreateNewVault(Location),

    // Write to the Vault.
    WriteToVault {
        location: Location,
        payload: Vec<u8>,
        hint: RecordHint,
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
    // Writes to the snapshot file. Accepts the snapshot key, an optional filename and an optional filepath.
    // Defaults to `$HOME/.engine/snapshots/backup.snapshot`.
    WriteSnapshot {
        key: snapshot::Key,
        filename: Option<String>,
        path: Option<PathBuf>,
    },
    // Helper to fill the snapshot state before the write operation.
    FillSnapshot,

    // Clear the cache of the bucket.
    ClearCache,

    // Interact with the runtime.
    ControlRequest(Procedure),
}

/// Messages that come from stronghold
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SHResults {
    ReturnWriteStore(StatusMessage),
    ReturnReadStore(Vec<u8>, StatusMessage),
    ReturnDeleteStore(StatusMessage),
    ReturnCreateVault(StatusMessage),
    ReturnWriteVault(StatusMessage),
    ReturnReadVault(Vec<u8>, StatusMessage),
    ReturnRevoke(StatusMessage),
    ReturnGarbage(StatusMessage),
    ReturnList(Vec<(RecordId, RecordHint)>, StatusMessage),
    ReturnFillSnap(StatusMessage),
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
                if let None = self.vault_exist($x) {
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
                let res = if let Some(_) = self.vault_exist(vid) {
                    true
                } else {
                    false
                };

                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnExistsVault(res), None)
                    .expect(line_error!());
            }
            SHRequest::CheckRecord { location } => {
                // let (vid, rid) = self.resolve_location(location);
                // Todo Add check by calling internal actor.
                // sender
                //     .as_ref()
                //     .expect(line_error!())
                //     .try_tell(SHResults::ReturnExistsRecord(res), None)
                //     .expect(line_error!());
            }
            SHRequest::CreateNewVault(location) => {
                let (vid, rid) = self.resolve_location(location);
                let client_str = self.get_client_str();

                self.add_new_vault(vid);

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
                let (vid, rid) = self.resolve_location(location);

                let client_str = self.get_client_str();

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::WriteToVault(vid, rid, payload, hint), sender);
            }

            #[cfg(test)]
            SHRequest::ReadFromVault { location } => {
                let (vid, rid) = self.resolve_location(location);

                let client_str = self.get_client_str();

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::ReadFromVault(vid, rid), sender);
            }
            SHRequest::RevokeData { location } => {
                let (vid, rid) = self.resolve_location(location);

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
            SHRequest::FillSnapshot => {
                let client_str = self.get_client_str();

                let internal = ctx
                    .select(&format!("/user/internal-{}/", client_str))
                    .expect(line_error!());

                internal.try_tell(InternalMsg::FillSnapshot { client: self.clone() }, sender)
            }
            SHRequest::WriteSnapshot { key, filename, path } => {
                let snapshot = ctx.select("/user/snapshot/").expect(line_error!());

                snapshot.try_tell(SMsg::WriteSnapshot { key, filename, path }, sender);
            }
            SHRequest::DeleteFromStore(loc) => {
                let (vid, _) = self.resolve_location(loc);

                self.store_delete_item(vid.into());

                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnDeleteStore(StatusMessage::Ok(())), None)
                    .expect(line_error!());
            }
            SHRequest::WriteToStore {
                location,
                payload,
                lifetime,
            } => {
                let (vid, _) = self.resolve_location(location);

                self.write_to_store(vid.into(), payload, lifetime);

                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnWriteStore(StatusMessage::Ok(())), None)
                    .expect(line_error!());
            }
            SHRequest::ReadFromStore { location } => {
                let (vid, _) = self.resolve_location(location);

                let payload = self.read_from_store(vid.into());

                if let Some(payload) = payload {
                    sender
                        .as_ref()
                        .expect(line_error!())
                        .try_tell(SHResults::ReturnReadStore(payload, StatusMessage::Ok(())), None)
                        .expect(line_error!());
                } else {
                    sender
                        .as_ref()
                        .expect(line_error!())
                        .try_tell(
                            SHResults::ReturnReadStore(
                                vec![],
                                StatusMessage::Error("Unable to read from store".into()),
                            ),
                            None,
                        )
                        .expect(line_error!());
                }
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
                        let (vid, rid) = self.resolve_location(output);

                        if let None = self.vault_exist(vid) {
                            self.add_new_vault(vid);
                        }

                        internal.try_tell(
                            InternalMsg::SLIP10Generate {
                                vault_id: vid,
                                record_id: rid,
                                hint,
                                size_bytes: size_bytes.unwrap_or(64),
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
                        let (seed_vault_id, seed_record_id) = self.resolve_location(seed);
                        ensure_vault_exists!(seed_vault_id, SLIP10Derive, "seed");

                        let (key_vault_id, key_record_id) = self.resolve_location(output);

                        if let None = self.vault_exist(key_vault_id) {
                            self.add_new_vault(key_vault_id);
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
                        let (parent_vault_id, parent_record_id) = self.resolve_location(parent);
                        ensure_vault_exists!(parent_vault_id, SLIP10Derive, "parent key");

                        let (child_vault_id, child_record_id) = self.resolve_location(output);

                        if let None = self.vault_exist(child_vault_id) {
                            self.add_new_vault(child_vault_id);
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
                        let (vault_id, record_id) = self.resolve_location(output);

                        if let None = self.vault_exist(vault_id) {
                            self.add_new_vault(vault_id);
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
                        let (vault_id, record_id) = self.resolve_location(output);

                        if let None = self.vault_exist(vault_id) {
                            self.add_new_vault(vault_id);
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
                    // Not implemented yet.
                    Procedure::BIP39MnemonicSentence { .. } => unimplemented!(),
                    Procedure::Ed25519PublicKey { private_key } => {
                        let (vault_id, record_id) = self.resolve_location(private_key);
                        internal.try_tell(InternalMsg::Ed25519PublicKey { vault_id, record_id }, sender)
                    }
                    Procedure::Ed25519Sign { private_key, msg } => {
                        let (vault_id, record_id) = self.resolve_location(private_key);
                        internal.try_tell(
                            InternalMsg::Ed25519Sign {
                                vault_id,
                                record_id,
                                msg,
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

            InternalResults::ReturnReadVault(payload, status) => {
                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnReadVault(payload, status), None)
                    .expect(line_error!());
            }
            InternalResults::ReturnList(list, status) => {
                sender
                    .as_ref()
                    .expect(line_error!())
                    .try_tell(SHResults::ReturnList(list, status), None)
                    .expect(line_error!());
            }
            InternalResults::RebuildCache {
                id,
                vaults,
                store,
                status,
            } => {
                self.clear_cache();

                self.rebuild_cache(id, vaults, store);

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
        }
    }
}
