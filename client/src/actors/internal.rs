// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::type_complexity)]

use riker::actors::*;

use std::{
    collections::{HashMap, HashSet},
    convert::TryFrom,
    path::PathBuf,
};

use engine::vault::{nvault::DbView, BoxProvider, ClientId, Key, RecordHint, RecordId, VaultId};

use stronghold_utils::GuardDebug;

use crypto::{
    keys::{
        bip39,
        slip10::{self, Chain, Curve, Seed},
    },
    signatures::ed25519,
    utils::rand::fill,
};

use engine::snapshot;

use crate::{
    actors::{snapshot::SMsg, ProcResult},
    internals::Provider,
    line_error,
    state::{
        client::{Client, ClientMsg, Store},
        key_store::KeyStore,
    },
    utils::{ResultMessage, StatusMessage},
};

pub struct InternalActor<P: BoxProvider + Send + Sync + Clone + 'static> {
    client_id: ClientId,
    keystore: KeyStore<P>,
    db: DbView<P>,
}

/// Messages used for the KeyStore Actor.
#[derive(Clone, GuardDebug)]
pub enum InternalMsg {
    CreateVault(VaultId, RecordId),
    #[cfg(test)]
    ReadFromVault(VaultId, RecordId),
    WriteToVault(VaultId, RecordId, Vec<u8>, RecordHint),
    RevokeData(VaultId, RecordId),
    GarbageCollect(VaultId),
    ListIds(VaultId),

    ReadSnapshot(
        snapshot::Key,
        Option<String>,
        Option<PathBuf>,
        ClientId,
        Option<ClientId>,
    ),
    ReloadData {
        id: ClientId,
        data: Box<(HashMap<VaultId, Key<Provider>>, DbView<Provider>, Store)>,
        status: StatusMessage,
    },
    ClearCache,
    KillInternal,
    FillSnapshot {
        client: Client,
    },

    SLIP10Generate {
        vault_id: VaultId,
        record_id: RecordId,
        hint: RecordHint,
        size_bytes: usize,
    },
    SLIP10DeriveFromSeed {
        chain: Chain,
        seed_vault_id: VaultId,
        seed_record_id: RecordId,
        key_vault_id: VaultId,
        key_record_id: RecordId,
        hint: RecordHint,
    },
    SLIP10DeriveFromKey {
        chain: Chain,
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
#[derive(Clone, GuardDebug)]
pub enum InternalResults {
    ReturnCreateVault(StatusMessage),
    ReturnWriteVault(StatusMessage),
    ReturnReadVault(Vec<u8>, StatusMessage),
    ReturnRevoke(StatusMessage),
    ReturnGarbage(StatusMessage),
    ReturnList(Vec<(RecordId, RecordHint)>, StatusMessage),
    ReturnWriteSnap(StatusMessage),
    ReturnControlRequest(ProcResult),
    RebuildCache {
        id: ClientId,
        vaults: HashSet<VaultId>,
        store: Store,
        status: StatusMessage,
    },
    ReturnClearCache(StatusMessage),
}

impl ActorFactoryArgs<ClientId> for InternalActor<Provider> {
    fn create_args(id: ClientId) -> Self {
        let db = DbView::new();
        let keystore = KeyStore::new();

        Self {
            db,
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
            InternalMsg::CreateVault(vid, _rid) => {
                let key = self.keystore.create_key(vid);
                self.db.init_vault(&key, vid).expect(line_error!());

                let cstr: String = self.client_id.into();

                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                client.try_tell(
                    ClientMsg::InternalResults(InternalResults::ReturnCreateVault(StatusMessage::OK)),
                    sender,
                );
            }
            #[cfg(test)]
            InternalMsg::ReadFromVault(vid, rid) => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());

                if let Some(key) = self.keystore.get_key(vid) {
                    let mut data: Vec<u8> = Vec::new();

                    self.db
                        .get_guard(&key, vid, rid, |gdata| {
                            let gdata = gdata.borrow();
                            data.extend_from_slice(&*gdata);

                            Ok(())
                        })
                        .expect(line_error!());

                    self.keystore.insert_key(vid, key);

                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnReadVault(data, StatusMessage::OK)),
                        sender,
                    );
                } else {
                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnReadVault(
                            vec![],
                            StatusMessage::Error("Vault does not exist.".into()),
                        )),
                        sender,
                    );
                }
            }
            InternalMsg::WriteToVault(vid, rid, payload, hint) => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());

                if let Some(key) = self.keystore.get_key(vid) {
                    self.db
                        .write(&key, vid, rid, payload.as_slice(), hint)
                        .expect(line_error!());

                    self.keystore.insert_key(vid, key);

                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnWriteVault(StatusMessage::OK)),
                        sender,
                    );
                } else {
                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnWriteVault(StatusMessage::Error(
                            "Vault does not exist".into(),
                        ))),
                        sender,
                    );
                }
            }

            InternalMsg::RevokeData(vid, rid) => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                if let Some(key) = self.keystore.get_key(vid) {
                    self.db.revoke_record(&key, vid, rid).expect(line_error!());

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
                    self.db.garbage_collect_vault(&key, vid).expect(line_error!());

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
            InternalMsg::ListIds(vid) => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                if let Some(key) = self.keystore.get_key(vid) {
                    let ids = self.db.list_hints_and_ids(&key, vid).expect(line_error!());

                    self.keystore.insert_key(vid, key);

                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnList(ids, StatusMessage::OK)),
                        sender,
                    );
                } else {
                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnList(
                            vec![],
                            StatusMessage::Error("Failed to get list, vault wasn't found".into()),
                        )),
                        sender,
                    );
                }
            }
            InternalMsg::ReloadData { id, data, status } => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());

                let (keystore, state, store) = *data;

                let vids = keystore.keys().map(|v| *v).collect::<HashSet<VaultId>>();

                self.keystore.rebuild_keystore(keystore);

                self.db = state;

                client.try_tell(
                    ClientMsg::InternalResults(InternalResults::RebuildCache {
                        id,
                        vaults: vids,
                        status: status,
                        store,
                    }),
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
                self.keystore.clear_keys();
                self.db.clear().expect(line_error!());

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
                size_bytes,
            } => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());

                let key = if !self.keystore.vault_exists(vault_id) {
                    let key = self.keystore.create_key(vault_id);
                    self.db.init_vault(&key, vault_id).expect(line_error!());

                    key
                } else {
                    self.keystore.get_key(vault_id).expect(line_error!())
                };

                self.keystore.insert_key(vault_id, key.clone());

                let mut seed = vec![0u8; size_bytes];
                fill(&mut seed).expect(line_error!());

                self.db
                    .write(&key, vault_id, record_id, &seed, hint)
                    .expect(line_error!());

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
                        self.keystore.insert_key(seed_vault_id, seed_key.clone());
                        let dk_key = if !self.keystore.vault_exists(key_vault_id) {
                            let key = self.keystore.create_key(key_vault_id);
                            self.db.init_vault(&key, key_vault_id).expect(line_error!());

                            key
                        } else {
                            self.keystore.get_key(key_vault_id).expect(line_error!())
                        };
                        self.keystore.insert_key(key_vault_id, dk_key.clone());

                        self.db
                            .exec_proc(
                                &seed_key,
                                seed_vault_id,
                                seed_record_id,
                                &dk_key,
                                key_vault_id,
                                key_record_id,
                                hint,
                                |gdata| {
                                    let dk = Seed::from_bytes(&gdata.borrow())
                                        .derive(Curve::Ed25519, &chain)
                                        .expect(line_error!());

                                    let data: Vec<u8> = dk.into();

                                    client.try_tell(
                                        ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                                            ProcResult::SLIP10Derive(ResultMessage::Ok(dk.chain_code())),
                                        )),
                                        sender,
                                    );

                                    Ok(data)
                                },
                            )
                            .expect(line_error!());
                    }
                    _ => client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnControlRequest(ProcResult::SLIP10Derive(
                            ResultMessage::Error("Failed to access vault".into()),
                        ))),
                        sender,
                    ),
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
                        self.keystore.insert_key(parent_vault_id, parent_key.clone());
                        let child_key = if !self.keystore.vault_exists(child_vault_id) {
                            let key = self.keystore.create_key(child_vault_id);
                            self.db.init_vault(&key, child_vault_id).expect(line_error!());

                            key
                        } else {
                            self.keystore.get_key(child_vault_id).expect(line_error!())
                        };

                        self.keystore.insert_key(child_vault_id, child_key.clone());

                        self.db
                            .exec_proc(
                                &parent_key,
                                parent_vault_id,
                                parent_record_id,
                                &child_key,
                                child_vault_id,
                                child_record_id,
                                hint,
                                |parent| {
                                    let parent = slip10::Key::try_from(&*parent.borrow()).expect(line_error!());
                                    let dk = parent.derive(&chain).expect(line_error!());

                                    let data: Vec<u8> = dk.into();

                                    client.try_tell(
                                        ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                                            ProcResult::SLIP10Derive(ResultMessage::Ok(dk.chain_code())),
                                        )),
                                        sender,
                                    );

                                    Ok(data)
                                },
                            )
                            .expect(line_error!());
                    }
                    _ => client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnControlRequest(ProcResult::SLIP10Derive(
                            ResultMessage::Error("Failed to access vault".into()),
                        ))),
                        sender,
                    ),
                }
            }
            InternalMsg::BIP39Generate {
                passphrase,
                vault_id,
                record_id,
                hint,
            } => {
                let mut entropy = [0u8; 32];
                fill(&mut entropy).expect(line_error!());

                let mnemonic = bip39::wordlist::encode(
                    &entropy,
                    &bip39::wordlist::ENGLISH, // TODO: make this user configurable
                )
                .expect(line_error!());

                let mut seed = [0u8; 64];
                bip39::mnemonic_to_seed(&mnemonic, &passphrase, &mut seed);

                let key = if !self.keystore.vault_exists(vault_id) {
                    let k = self.keystore.create_key(vault_id);
                    self.db.init_vault(&k, vault_id).expect(line_error!());

                    k
                } else {
                    self.keystore.get_key(vault_id).expect(line_error!())
                };

                self.keystore.insert_key(vault_id, key.clone());

                // TODO: also store the mnemonic to be able to export it in the
                // BIP39MnemonicSentence message
                self.db
                    .write(&key, vault_id, record_id, &seed, hint)
                    .expect(line_error!());

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
                    let k = self.keystore.create_key(vault_id);
                    self.db.init_vault(&k, vault_id).expect(line_error!());

                    k
                } else {
                    self.keystore.get_key(vault_id).expect(line_error!())
                };

                self.keystore.insert_key(vault_id, key.clone());

                let mut seed = [0u8; 64];
                bip39::mnemonic_to_seed(&mnemonic, &passphrase, &mut seed);

                // TODO: also store the mnemonic to be able to export it in the
                // BIP39MnemonicSentence message
                self.db
                    .write(&key, vault_id, record_id, &seed, hint)
                    .expect(line_error!());

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
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());

                if let Some(key) = self.keystore.get_key(vault_id) {
                    self.keystore.insert_key(vault_id, key.clone());

                    self.db
                        .get_guard(&key, vault_id, record_id, |data| {
                            let raw = data.borrow();
                            let mut raw = (*raw).to_vec();

                            if raw.len() < 32 {
                                client.try_tell(
                                    ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                                        ProcResult::Ed25519PublicKey(ResultMessage::Error(
                                            "Incorrect number of key bytes".into(),
                                        )),
                                    )),
                                    sender.clone(),
                                );
                            }
                            raw.truncate(32);
                            let mut bs = [0; 32];
                            bs.copy_from_slice(&raw);
                            let sk = ed25519::SecretKey::from_le_bytes(bs).expect(line_error!());
                            let pk = sk.public_key();

                            client.try_tell(
                                ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                                    ProcResult::Ed25519PublicKey(ResultMessage::Ok(pk.to_compressed_bytes())),
                                )),
                                sender,
                            );

                            Ok(())
                        })
                        .expect(line_error!());
                } else {
                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                            ProcResult::Ed25519PublicKey(ResultMessage::Error("Failed to access vault".into())),
                        )),
                        sender,
                    )
                }
            }
            InternalMsg::Ed25519Sign {
                vault_id,
                record_id,
                msg,
            } => {
                let cstr: String = self.client_id.into();
                let client = ctx.select(&format!("/user/{}/", cstr)).expect(line_error!());
                if let Some(pkey) = self.keystore.get_key(vault_id) {
                    self.keystore.insert_key(vault_id, pkey.clone());

                    self.db
                        .get_guard(&pkey, vault_id, record_id, |data| {
                            let raw = data.borrow();
                            let mut raw = (*raw).to_vec();

                            if raw.len() <= 32 {
                                client.try_tell(
                                    ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                                        ProcResult::Ed25519Sign(ResultMessage::Error(
                                            "incorrect number of key bytes".into(),
                                        )),
                                    )),
                                    sender.clone(),
                                );
                            }
                            raw.truncate(32);
                            let mut bs = [0; 32];
                            bs.copy_from_slice(&raw);
                            let sk = ed25519::SecretKey::from_le_bytes(bs).expect(line_error!());

                            let sig = sk.sign(&msg);

                            client.try_tell(
                                ClientMsg::InternalResults(InternalResults::ReturnControlRequest(
                                    ProcResult::Ed25519Sign(ResultMessage::Ok(sig.to_bytes())),
                                )),
                                sender,
                            );

                            Ok(())
                        })
                        .expect(line_error!());
                } else {
                    client.try_tell(
                        ClientMsg::InternalResults(InternalResults::ReturnControlRequest(ProcResult::Ed25519Sign(
                            ResultMessage::Error("Failed to access vault".into()),
                        ))),
                        sender,
                    )
                }
            }
            InternalMsg::FillSnapshot { client } => {
                let snapshot = ctx.select("/user/snapshot/").expect(line_error!());

                let keys = self.keystore.get_data();
                let db = self.db.clone();
                let store = client.store;
                let id = client.client_id;

                snapshot.try_tell(
                    SMsg::FillSnapshot {
                        id,
                        data: Box::from((keys, db, store)),
                    },
                    sender,
                );
            }
        }
    }
}
