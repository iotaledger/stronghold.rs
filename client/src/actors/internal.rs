// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::type_complexity)]

use riker::actors::*;

use std::{collections::BTreeMap, convert::TryFrom, fmt::Debug, path::PathBuf};

use engine::vault::{BoxProvider, Key, ReadResult, RecordHint, RecordId};

use engine::snapshot;

use crate::{
    actors::{ProcResult, SMsg},
    bucket::Bucket,
    client::{Client, ClientMsg},
    internals::Provider,
    key_store::KeyStore,
    line_error,
    utils::{hd, ResultMessage, StatusMessage, VaultId},
    ClientId,
};

pub struct InternalActor<P: BoxProvider + Send + Sync + Clone + 'static> {
    client_id: ClientId,
    bucket: Bucket<P>,
    keystore: KeyStore<P>,
}

/// Messages used for the KeyStore Actor.
#[derive(Clone, Debug)]
pub enum InternalMsg {
    CreateVault(VaultId, RecordId),
    ReadData(VaultId, RecordId),
    WriteData(VaultId, RecordId, Vec<u8>, RecordHint),
    InitRecord(VaultId, RecordId),
    RevokeData(VaultId, RecordId),
    GarbageCollect(VaultId),
    ListIds(Vec<u8>, VaultId),

    ReadSnapshot(
        snapshot::Key,
        Option<String>,
        Option<PathBuf>,
        ClientId,
        Option<ClientId>,
    ),
    ReloadData(
        (
            crate::client::Client,
            BTreeMap<VaultId, Key<Provider>>,
            BTreeMap<Key<Provider>, Vec<ReadResult>>,
        ),
        StatusMessage,
    ),
    ClearCache,
    KillInternal,
    WriteSnapshotAll {
        key: snapshot::Key,
        filename: Option<String>,
        path: Option<PathBuf>,
        data: Client,
        id: ClientId,
        is_final: bool,
    },

    SLIP10Generate {
        vault_id: VaultId,
        record_id: RecordId,
        hint: RecordHint,
    },
    SLIP10DeriveFromSeed {
        chain: hd::Chain,
        seed_vault_id: VaultId,
        seed_record_id: RecordId,
        key_vault_id: VaultId,
        key_record_id: RecordId,
        hint: RecordHint,
    },
    SLIP10DeriveFromKey {
        chain: hd::Chain,
        parent_vault_id: VaultId,
        parent_record_id: RecordId,
        child_vault_id: VaultId,
        child_record_id: RecordId,
        hint: RecordHint,
    },
    BIP39Generate {
        passphrase: String,
        vault_id: VaultId,
        record_id: RecordId,
        hint: RecordHint,
    },
    BIP39Recover {
        mnemonic: String,
        passphrase: String,
        vault_id: VaultId,
        record_id: RecordId,
        hint: RecordHint,
    },
    Ed25519PublicKey {
        vault_id: VaultId,
        record_id: RecordId,
    },
    Ed25519Sign {
        vault_id: VaultId,
        record_id: RecordId,
        msg: Vec<u8>,
    },
    SignUnlockBlock {
        vault_id: VaultId,
        record_id: RecordId,
        path: hd::Chain,
        essence: Vec<u8>,
    },
}

/// Messages used internally by the client.
#[derive(Clone, Debug)]
pub enum InternalResults {
    ReturnCreateVault(StatusMessage),
    ReturnWriteData(StatusMessage),
    ReturnInitRecord(StatusMessage),
    ReturnReadData(Vec<u8>, StatusMessage),
    ReturnRevoke(StatusMessage),
    ReturnGarbage(StatusMessage),
    ReturnList(Vec<u8>, Vec<(RecordId, RecordHint)>, StatusMessage),
    ReturnWriteSnap(StatusMessage),
    ReturnControlRequest(ProcResult),
    RebuildCache(Client, StatusMessage),
    ReturnClearCache(StatusMessage),
}

impl ActorFactoryArgs<ClientId> for InternalActor<Provider> {
    fn create_args(id: ClientId) -> Self {
        let bucket = Bucket::new();
        let keystore = KeyStore::new();

        Self {
            bucket,
            keystore,
            client_id: id,
        }
    }
}

impl Actor for InternalActor<Provider> {
    type Msg = InternalMsg;

    fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        self.receive(ctx, msg, sender);
    }
}

impl Receive<InternalMsg> for InternalActor<Provider> {
    type Msg = InternalMsg;

    fn receive(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        match msg {
            InternalMsg::CreateVault(vid, rid) => {
                let key = self.keystore.create_key(vid);

                self.bucket.create_and_init_vault(key, rid);

                let cstr: String = self.client_id.into();

                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                client.try_tell(
                    ClientMsg::InternalResults(InternalResults::ReturnCreateVault(StatusMessage::OK)),
                    sender,
                );
            }
            InternalMsg::ReadData(vid, rid) => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());

                if let Some(key) = self.keystore.get_key(vid) {
                    let plain = self.bucket.read_data(key.clone(), rid);

                    self.keystore.insert_key(vid, key);

                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnReadData(plain, StatusMessage::OK)),
                        sender,
                    );
                } else {
                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnReadData(
                            vec![],
                            StatusMessage::Error("Vault does not exist.".into()),
                        )),
                        sender,
                    );
                }
            }
            InternalMsg::WriteData(vid, rid, payload, hint) => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());

                if let Some(key) = self.keystore.get_key(vid) {
                    self.bucket.write_payload(key.clone(), rid, payload, hint);

                    self.keystore.insert_key(vid, key);

                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnWriteData(StatusMessage::OK)),
                        sender,
                    );
                } else {
                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnWriteData(StatusMessage::Error(
                            "Vault does not exist".into(),
                        ))),
                        sender,
                    );
                }
            }
            InternalMsg::InitRecord(vid, rid) => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                if let Some(key) = self.keystore.get_key(vid) {
                    let _rid = self.bucket.init_record(key.clone(), rid);

                    self.keystore.insert_key(vid, key);

                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnInitRecord(StatusMessage::OK)),
                        sender,
                    );
                }
            }
            InternalMsg::RevokeData(vid, rid) => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                if let Some(key) = self.keystore.get_key(vid) {
                    self.bucket.revoke_data(key.clone(), rid);

                    self.keystore.insert_key(vid, key);

                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnRevoke(StatusMessage::OK)),
                        sender,
                    );
                } else {
                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnRevoke(StatusMessage::Error(
                            "Failed to revoke record, vault wasn't found".into(),
                        ))),
                        sender,
                    );
                }
            }
            InternalMsg::GarbageCollect(vid) => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                if let Some(key) = self.keystore.get_key(vid) {
                    self.bucket.garbage_collect(key.clone());

                    self.keystore.insert_key(vid, key);

                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnGarbage(StatusMessage::OK)),
                        sender,
                    );
                } else {
                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnGarbage(StatusMessage::Error(
                            "Failed to garbage collect, vault wasn't found".into(),
                        ))),
                        sender,
                    );
                }
            }
            InternalMsg::ListIds(vault_path, vid) => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                if let Some(key) = self.keystore.get_key(vid) {
                    let ids = self.bucket.list_ids(key.clone());

                    self.keystore.insert_key(vid, key);

                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnList(vault_path, ids, StatusMessage::OK)),
                        sender,
                    );
                } else {
                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnList(
                            vault_path,
                            vec![],
                            StatusMessage::Error("Failed to get list, vault wasn't found".into()),
                        )),
                        sender,
                    );
                }
            }
            InternalMsg::ReloadData((client_data, keystore, state), status) => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());

                self.keystore.rebuild_keystore(keystore);
                self.bucket.repopulate_data(state);

                client.try_tell(
                    ClientMsg::InternalResults(InternalResults::RebuildCache(client_data, status)),
                    sender,
                );
            }

            InternalMsg::ReadSnapshot(key, filename, path, id, fid) => {
                let snapshot = ctx.select("/user/snapshot/").expect(line_error!());
                snapshot.try_tell(
                    SMsg::ReadFromSnapshot {
                        key,
                        filename,
                        path,
                        id,
                        fid,
                    },
                    sender,
                );
            }
            InternalMsg::ClearCache => {
                self.bucket.clear_cache();
                self.keystore.clear_keys();

                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                client.try_tell(
                    ClientMsg::InternalResults(InternalResults::ReturnClearCache(StatusMessage::OK)),
                    sender,
                );
            }
            InternalMsg::KillInternal => {
                ctx.stop(ctx.myself());
            }
            InternalMsg::SLIP10Generate {
                vault_id,
                record_id,
                hint,
            } => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());

                let key = if !self.keystore.vault_exists(vault_id) {
                    self.keystore.create_key(vault_id)
                } else {
                    self.keystore.get_key(vault_id).expect(line_error!())
                };

                self.keystore.insert_key(vault_id, key.clone());

                if !self.bucket.record_exists_in_vault(key.clone(), record_id) {
                    self.bucket.create_and_init_vault(key.clone(), record_id);
                }

                let mut seed = [0u8; 64];
                crypto::rand::fill(&mut seed).expect(line_error!());

                self.bucket.write_payload(key, record_id, seed.to_vec(), hint);

                client.try_tell(
                    ClientMsg::InternalResults(InternalResults::ReturnControlRequest(ProcResult::SLIP10Generate(
                        StatusMessage::OK,
                    ))),
                    sender,
                );
            }
            InternalMsg::SLIP10DeriveFromSeed {
                chain,
                seed_vault_id,
                seed_record_id,
                key_vault_id,
                key_record_id,
                hint,
            } => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());

                match self.keystore.get_key(seed_vault_id) {
                    Some(seed_key) => {
                        let plain = self.bucket.read_data(seed_key.clone(), seed_record_id);
                        self.keystore.insert_key(seed_vault_id, seed_key);
                        let dk = hd::Seed::from_bytes(&plain).derive(&chain).expect(line_error!());

                        let dk_key = if !self.keystore.vault_exists(key_vault_id) {
                            self.keystore.create_key(key_vault_id)
                        } else {
                            self.keystore.get_key(key_vault_id).expect(line_error!())
                        };
                        self.keystore.insert_key(key_vault_id, dk_key.clone());

                        if !self.bucket.record_exists_in_vault(dk_key.clone(), key_record_id) {
                            self.bucket.create_and_init_vault(dk_key.clone(), key_record_id);
                        }

                        self.bucket.write_payload(dk_key, key_record_id, dk.into(), hint);

                        client.try_tell(
                            ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                                ProcResult::SLIP10Derive(StatusMessage::Ok(())),
                            )),
                            sender,
                        );
                    }
                    _ => todo!("return error message"),
                }
            }
            InternalMsg::SLIP10DeriveFromKey {
                chain,
                parent_vault_id,
                parent_record_id,
                child_vault_id,
                child_record_id,
                hint,
            } => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());

                match self.keystore.get_key(parent_vault_id) {
                    Some(parent_key) => {
                        let parent = self.bucket.read_data(parent_key.clone(), parent_record_id);
                        self.keystore.insert_key(parent_vault_id, parent_key);

                        let parent = hd::Key::try_from(parent.as_slice()).expect(line_error!());
                        let dk = parent.derive(&chain).expect(line_error!());

                        let child_key = if !self.keystore.vault_exists(child_vault_id) {
                            self.keystore.create_key(child_vault_id)
                        } else {
                            self.keystore.get_key(child_vault_id).expect(line_error!())
                        };

                        self.keystore.insert_key(child_vault_id, child_key.clone());

                        if !self.bucket.record_exists_in_vault(child_key.clone(), child_record_id) {
                            self.bucket.create_and_init_vault(child_key.clone(), child_record_id);
                        }

                        self.bucket.write_payload(child_key, child_record_id, dk.into(), hint);

                        client.try_tell(
                            ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                                ProcResult::SLIP10Derive(StatusMessage::Ok(())),
                            )),
                            sender,
                        );
                    }
                    _ => todo!("return error message"),
                }
            }
            InternalMsg::BIP39Generate {
                passphrase,
                vault_id,
                record_id,
                hint,
            } => {
                let mut entropy = [0u8; 32];
                crypto::rand::fill(&mut entropy).expect(line_error!());

                let mnemonic = crypto::bip39::wordlist::encode(
                    &entropy,
                    &crypto::bip39::wordlist::ENGLISH, // TODO: make this user configurable
                )
                .expect(line_error!());

                let mut seed = [0u8; 64];
                crypto::bip39::mnemonic_to_seed(&mnemonic, &passphrase, &mut seed);

                let key = if !self.keystore.vault_exists(vault_id) {
                    self.keystore.create_key(vault_id)
                } else {
                    self.keystore.get_key(vault_id).expect(line_error!())
                };

                self.keystore.insert_key(vault_id, key.clone());

                if !self.bucket.record_exists_in_vault(key.clone(), record_id) {
                    self.bucket.create_and_init_vault(key.clone(), record_id);
                }

                // TODO: also store the mnemonic to be able to export it in the
                // BIP39MnemonicSentence message
                self.bucket.write_payload(key, record_id, seed.to_vec(), hint);

                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                client.try_tell(
                    ClientMsg::InternalResults(InternalResults::ReturnControlRequest(ProcResult::BIP39Generate(
                        StatusMessage::OK,
                    ))),
                    sender,
                );
            }
            InternalMsg::BIP39Recover {
                mnemonic,
                passphrase,
                vault_id,
                record_id,
                hint,
            } => {
                let key = if !self.keystore.vault_exists(vault_id) {
                    self.keystore.create_key(vault_id)
                } else {
                    self.keystore.get_key(vault_id).expect(line_error!())
                };

                self.keystore.insert_key(vault_id, key.clone());

                if !self.bucket.record_exists_in_vault(key.clone(), record_id) {
                    self.bucket.create_and_init_vault(key.clone(), record_id);
                }

                let mut seed = [0u8; 64];
                crypto::bip39::mnemonic_to_seed(&mnemonic, &passphrase, &mut seed);

                // TODO: also store the mnemonic to be able to export it in the
                // BIP39MnemonicSentence message
                self.bucket.write_payload(key, record_id, seed.to_vec(), hint);

                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                client.try_tell(
                    ClientMsg::InternalResults(InternalResults::ReturnControlRequest(ProcResult::BIP39Recover(
                        StatusMessage::OK,
                    ))),
                    sender,
                );
            }
            InternalMsg::Ed25519PublicKey { vault_id, record_id } => {
                let key = match self.keystore.get_key(vault_id) {
                    Some(key) => key,
                    None => todo!("return error message"),
                };
                self.keystore.insert_key(vault_id, key.clone());

                let mut raw = self.bucket.read_data(key, record_id);
                if raw.len() < 32 {
                    todo!("return error message: insufficient bytes")
                }
                raw.truncate(32);
                let mut bs = [0; 32];
                bs.copy_from_slice(&raw);
                let sk = crypto::ed25519::SecretKey::from_le_bytes(bs).expect(line_error!());
                let pk = sk.public_key();

                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                client.try_tell(
                    ClientMsg::InternalResults(InternalResults::ReturnControlRequest(ProcResult::Ed25519PublicKey(
                        ResultMessage::Ok(pk.to_compressed_bytes()),
                    ))),
                    sender,
                );
            }
            InternalMsg::Ed25519Sign {
                vault_id,
                record_id,
                msg,
            } => {
                let key = match self.keystore.get_key(vault_id) {
                    Some(key) => key,
                    None => todo!("return error message"),
                };
                self.keystore.insert_key(vault_id, key.clone());

                let mut raw = self.bucket.read_data(key, record_id);
                if raw.len() < 32 {
                    todo!("return error message: insufficient bytes")
                }
                raw.truncate(32);
                let mut bs = [0; 32];
                bs.copy_from_slice(&raw);
                let sk = crypto::ed25519::SecretKey::from_le_bytes(bs).expect(line_error!());
                let sig = sk.sign(&msg);

                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                client.try_tell(
                    ClientMsg::InternalResults(InternalResults::ReturnControlRequest(ProcResult::Ed25519Sign(
                        ResultMessage::Ok(sig.to_bytes()),
                    ))),
                    sender,
                );
            }
            InternalMsg::SignUnlockBlock {
                vault_id,
                record_id,
                path,
                essence,
            } => {
                let key = match self.keystore.get_key(vault_id) {
                    Some(key) => key,
                    None => todo!("return error message"),
                };

                self.keystore.insert_key(vault_id, key.clone());

                let mut raw = self.bucket.read_data(key, record_id);
                if raw.len() < 32 {
                    todo!("return error message: insufficient bytes")
                }
                raw.truncate(32);
                let mut bs = [0; 32];
                bs.copy_from_slice(&raw);

                let sk = crypto::ed25519::SecretKey::from_le_bytes(bs).expect(line_error!());

                let sig = sk.sign(&essence);

                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                client.try_tell(
                    ClientMsg::InternalResults(InternalResults::ReturnControlRequest(ProcResult::SignUnlockBlock(
                        ResultMessage::Ok(sig.to_bytes()),
                        ResultMessage::Ok(sk.public_key().to_compressed_bytes()),
                    ))),
                    sender,
                );
            }
            InternalMsg::WriteSnapshotAll {
                key,
                filename,
                path,
                data,
                id,
                is_final,
            } => {
                let snapshot = ctx.select("/user/snapshot/").expect(line_error!());

                snapshot.try_tell(
                    SMsg::WriteSnapshotAll {
                        key,
                        filename,
                        path,
                        id,
                        is_final,
                        data: (data, self.keystore.get_data(), self.bucket.get_data()),
                    },
                    sender,
                );
            }
        }
    }
}
