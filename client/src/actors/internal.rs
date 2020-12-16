// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use riker::actors::*;

use std::{convert::TryFrom, fmt::Debug, path::PathBuf};

use engine::vault::{BoxProvider, RecordHint, RecordId};

use engine::snapshot;

use crate::{
    actors::{ProcResult, SMsg},
    bucket::Bucket,
    client::ClientMsg,
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
    WriteSnapshot(snapshot::Key, Option<String>, Option<PathBuf>, String),
    ReadSnapshot(snapshot::Key, Option<String>, Option<PathBuf>, String),
    ReloadData(Vec<u8>, Vec<u8>, StatusMessage),
    ClearCache,
    KillInternal,

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
}

/// Messages used internally by the client.
#[derive(Clone, Debug)]
pub enum InternalResults {
    ReturnCreateVault(StatusMessage),
    ReturnWriteData(StatusMessage),
    ReturnInitRecord(VaultId, RecordId, StatusMessage),
    ReturnReadData(Vec<u8>, StatusMessage),
    ReturnRevoke(StatusMessage),
    ReturnGarbage(StatusMessage),
    ReturnList(Vec<u8>, Vec<(RecordId, RecordHint)>, StatusMessage),
    ReturnWriteSnap(StatusMessage),
    ReturnControlRequest(ProcResult),
    RebuildCache(Vec<VaultId>, Vec<Vec<RecordId>>, StatusMessage),
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
                    ClientMsg::InternalResults(InternalResults::ReturnCreateVault(StatusMessage::Ok)),
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
                        ClientMsg::InternalResults(InternalResults::ReturnReadData(plain, StatusMessage::Ok)),
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
                        ClientMsg::InternalResults(InternalResults::ReturnWriteData(StatusMessage::Ok)),
                        sender,
                    );
                } else {
                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnWriteData(StatusMessage::Error(
                            "Vault doesn't exist".into(),
                        ))),
                        sender,
                    );
                }
            }
            InternalMsg::InitRecord(vid, rid) => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                if let Some(key) = self.keystore.get_key(vid) {
                    let rid = self.bucket.init_record(key.clone(), rid);

                    self.keystore.insert_key(vid, key);

                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnInitRecord(vid, rid, StatusMessage::Ok)),
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
                        ClientMsg::InternalResults(InternalResults::ReturnRevoke(StatusMessage::Ok)),
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
                        ClientMsg::InternalResults(InternalResults::ReturnGarbage(StatusMessage::Ok)),
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
                        ClientMsg::InternalResults(InternalResults::ReturnList(vault_path, ids, StatusMessage::Ok)),
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
            InternalMsg::ReloadData(cache, keystore, status) => {
                let (_, rids) = self.bucket.repopulate_data(cache);

                let vids = self.keystore.rebuild_keystore(keystore);

                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                client.try_tell(
                    ClientMsg::InternalResults(InternalResults::RebuildCache(vids, rids, status)),
                    sender,
                );
            }
            InternalMsg::WriteSnapshot(pass, name, path, client_str) => {
                let cache = self.bucket.offload_data();
                let store = self.keystore.offload_data();

                let snapshot = ctx.select("/user/snapshot/").expect(line_error!());
                snapshot.try_tell(
                    SMsg::WriteSnapshot(pass, name, path, (cache, store), client_str),
                    sender,
                );
            }
            InternalMsg::ReadSnapshot(pass, name, path, client_str) => {
                let snapshot = ctx.select("/user/snapshot/").expect(line_error!());
                snapshot.try_tell(SMsg::ReadSnapshot(pass, name, path, client_str), sender);
            }
            InternalMsg::ClearCache => {
                self.bucket.clear_cache();
                self.keystore.clear_keys();
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

                let key = self.keystore.create_key(vault_id);

                self.bucket.create_and_init_vault(key.clone(), record_id);

                let mut seed = [0u8; 64];
                crypto::rand::fill(&mut seed).expect(line_error!());

                self.bucket.write_payload(key, record_id, seed.to_vec(), hint);

                client.try_tell(
                    ClientMsg::InternalResults(InternalResults::ReturnControlRequest(ProcResult::SLIP10Generate {
                        status: StatusMessage::Ok,
                    })),
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
                        let plain = self.bucket.read_data(seed_key, seed_record_id);
                        let dk = hd::Seed::from_bytes(&plain).derive(&chain).expect(line_error!());

                        let dk_key = self.keystore.create_key(key_vault_id);
                        let krid = self.bucket.init_record(dk_key.clone(), key_record_id);
                        self.bucket.write_payload(dk_key, krid, dk.into(), hint);

                        client.try_tell(
                            ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                                ProcResult::SLIP10Derive {
                                    status: StatusMessage::Ok,
                                },
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
                        let parent = self.bucket.read_data(parent_key, parent_record_id);
                        let parent = hd::Key::try_from(parent.as_slice()).expect(line_error!());
                        let dk = parent.derive(&chain).expect(line_error!());

                        let child_key = self.keystore.create_key(child_vault_id);
                        let krid = self.bucket.init_record(child_key.clone(), child_record_id);
                        self.bucket.write_payload(child_key, krid, dk.into(), hint);

                        client.try_tell(
                            ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                                ProcResult::SLIP10Derive {
                                    status: StatusMessage::Ok,
                                },
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
                    crypto::bip39::wordlist::ENGLISH, // TODO: make this user configurable
                )
                .expect(line_error!());

                let mut seed = [0u8; 64];
                crypto::bip39::mnemonic_to_seed(&mnemonic, &passphrase, &mut seed);

                let key = self.keystore.create_key(vault_id);
                self.bucket.create_and_init_vault(key.clone(), record_id);

                // TODO: also store the mnemonic to be able to export it in the
                // BIP39MnemonicSentence message
                self.bucket.write_payload(key, record_id, seed.to_vec(), hint);

                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                client.try_tell(
                    ClientMsg::InternalResults(InternalResults::ReturnControlRequest(ProcResult::BIP39Generate {
                        status: StatusMessage::Ok,
                    })),
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
                let key = self.keystore.create_key(vault_id);
                self.bucket.create_and_init_vault(key.clone(), record_id);

                let mut seed = [0u8; 64];
                crypto::bip39::mnemonic_to_seed(&mnemonic, &passphrase, &mut seed);

                // TODO: also store the mnemonic to be able to export it in the
                // BIP39MnemonicSentence message
                self.bucket.write_payload(key, record_id, seed.to_vec(), hint);

                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                client.try_tell(
                    ClientMsg::InternalResults(InternalResults::ReturnControlRequest(ProcResult::BIP39Recover {
                        status: StatusMessage::Ok,
                    })),
                    sender,
                );
            }
            InternalMsg::Ed25519PublicKey { vault_id, record_id } => {
                let key = match self.keystore.get_key(vault_id) {
                    Some(key) => key,
                    None => todo!("return error message"),
                };

                let raw = self.bucket.read_data(key, record_id);
                if raw.len() < 32 {
                    todo!("return error message: insufficient bytes")
                }
                let mut bs = [0; 32];
                bs.copy_from_slice(&raw);
                let sk = crypto::ed25519::SecretKey::from_le_bytes(bs).expect(line_error!());
                let pk = sk.public_key();

                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                client.try_tell(
                    ClientMsg::InternalResults(InternalResults::ReturnControlRequest(ProcResult::Ed25519PublicKey {
                        result: ResultMessage::Ok(pk.to_compressed_bytes()),
                    })),
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

                let raw = self.bucket.read_data(key, record_id);
                if raw.len() < 32 {
                    todo!("return error message: insufficient bytes")
                }
                let mut bs = [0; 32];
                bs.copy_from_slice(&raw);
                let sk = crypto::ed25519::SecretKey::from_le_bytes(bs).expect(line_error!());
                let sig = sk.sign(&msg);

                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                client.try_tell(
                    ClientMsg::InternalResults(InternalResults::ReturnControlRequest(ProcResult::Ed25519Sign {
                        result: ResultMessage::Ok(sig.to_bytes()),
                    })),
                    sender,
                );
            }
        }
    }
}
