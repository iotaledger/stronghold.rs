// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Secure Actor module
//!
//! The secure actor runs as service, isolates contained data, and synchronizes
//! across multiple accesses.

#![allow(clippy::type_complexity)]

use crate::internals;
pub use crate::{
    actors::{GetSnapshot, Registry},
    internals::Provider,
    state::{key_store::KeyStore, secure::SecureClient, snapshot::Snapshot},
    utils::StatusMessage,
    ResultMessage,
};
use actix::{Actor, ActorContext, Context, Handler, Message, Supervised};

use crypto::{
    keys::{
        bip39,
        slip10::{self, Chain, Curve, Seed},
    },
    signatures::ed25519,
    utils::rand::fill,
};
use engine::{
    store::Cache,
    vault::{ClientId, DbView, Key, RecordHint, RecordId, VaultId},
};
use std::{
    cell::Cell,
    collections::{HashMap, HashSet},
    convert::TryFrom,
    rc::Rc,
};

use self::procedures::CallProcedure;
// sub-modules re-exports
pub use self::procedures::ProcResult;

/// Store typedef on `engine::store::Cache`
pub type Store = Cache<Vec<u8>, Vec<u8>>;

// #[cfg(feature = "communication")]
// use communication::actor::{PermissionValue, RequestPermissions, ToPermissionVariants, VariantPermission};

use stronghold_utils::GuardDebug;
use thiserror::Error as DeriveError;

#[derive(DeriveError, Debug)]
pub enum VaultError {
    #[error("Vault does not exist")]
    NotExisting,

    #[error("Failed to revoke record, vault does not exist")]
    RevokationError,

    #[error("Failed to collect gargabe, vault does not exist")]
    GargabeCollectError,

    #[error("Failed to get list, vault does not exist")]
    ListError,

    #[error("Failed to access Vault")]
    AccessError,
}

#[derive(DeriveError, Debug)]
pub enum SnapshotError {
    #[error("No snapshot present for client id ({0})")]
    NoSnapshotPresent(String),
}

/// Message types for [`SecureClientActor`]
pub mod messages {

    use super::*;
    use crate::{internals, Location};
    use std::time::Duration;

    #[derive(Clone, GuardDebug)]
    pub struct Terminate;

    impl Message for Terminate {
        type Result = ();
    }

    #[derive(Clone, GuardDebug)]
    pub struct ReloadData {
        pub id: ClientId,
        pub data: Box<(
            HashMap<VaultId, Key<internals::Provider>>,
            DbView<internals::Provider>,
            Store,
        )>,
    }

    impl Message for ReloadData {
        type Result = ();
    }

    #[derive(Clone, GuardDebug)]
    pub struct CreateVault {
        pub location: Location,
    }

    impl Message for CreateVault {
        type Result = ();
    }

    #[derive(Clone, GuardDebug)]
    pub struct WriteToVault {
        pub location: Location,

        pub payload: Vec<u8>,
        pub hint: RecordHint,
    }

    impl Message for WriteToVault {
        type Result = Result<(), anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct RevokeData {
        pub location: Location,
    }

    impl Message for RevokeData {
        type Result = Result<(), anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct GarbageCollect {
        pub location: Location,
    }

    impl Message for GarbageCollect {
        type Result = Result<(), anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct ListIds {
        pub vault_path: Vec<u8>,
    }

    impl Message for ListIds {
        type Result = Result<Vec<(RecordId, RecordHint)>, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct CheckRecord {
        pub location: Location,
    }

    impl Message for CheckRecord {
        type Result = bool;
    }

    #[derive(Clone, GuardDebug)]
    pub struct ClearCache;

    impl Message for ClearCache {
        type Result = Result<(), anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct CheckVault {
        pub vault_path: Vec<u8>,
    }

    impl Message for CheckVault {
        type Result = Result<(), anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct WriteToStore {
        pub location: Location,
        pub payload: Vec<u8>,
        pub lifetime: Option<Duration>,
    }

    impl Message for WriteToStore {
        type Result = Result<(), anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct ReadFromStore {
        pub location: Location,
    }

    impl Message for ReadFromStore {
        type Result = Result<Vec<u8>, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct DeleteFromStore {
        pub location: Location,
    }

    impl Message for DeleteFromStore {
        type Result = Result<(), anyhow::Error>;
    }

    pub struct GetData {}

    impl Message for GetData {
        type Result = Result<
            Box<(
                HashMap<VaultId, Key<internals::Provider>>,
                DbView<internals::Provider>,
                Store,
            )>,
            anyhow::Error,
        >;
    }
}

pub mod procedures {

    use super::*;
    use crate::Location;
    use crypto::keys::slip10::ChainCode;
    use serde::{Deserialize, Serialize};

    /// for old client (cryptographic) procedure calling
    pub enum Procedure {
        /// Generate a raw SLIP10 seed of the specified size (in bytes, defaults to 64 bytes/512 bits) and store it in
        /// the `output` location
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

    #[derive(GuardDebug)]
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

    #[derive(GuardDebug)]
    pub struct CallProcedure {
        pub proc: Procedure, // is procedure from client
    }

    impl Message for CallProcedure {
        type Result = Result<ProcResult, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct SLIP10Generate {
        pub vault_id: VaultId,
        pub record_id: RecordId,
        pub hint: RecordHint,
        pub size_bytes: usize,
    }

    impl Message for SLIP10Generate {
        type Result = Result<crate::ProcResult, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct SLIP10DeriveFromSeed {
        pub chain: Chain,
        pub seed_vault_id: VaultId,
        pub seed_record_id: RecordId,
        pub key_vault_id: VaultId,
        pub key_record_id: RecordId,
        pub hint: RecordHint,
    }

    impl Message for SLIP10DeriveFromSeed {
        type Result = Result<crate::ProcResult, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct SLIP10DeriveFromKey {
        pub chain: Chain,
        pub parent_vault_id: VaultId,
        pub parent_record_id: RecordId,
        pub child_vault_id: VaultId,
        pub child_record_id: RecordId,
        pub hint: RecordHint,
    }

    impl Message for SLIP10DeriveFromKey {
        type Result = Result<crate::ProcResult, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct BIP39Generate {
        pub passphrase: String,
        pub vault_id: VaultId,
        pub record_id: RecordId,
        pub hint: RecordHint,
    }

    impl Message for BIP39Generate {
        type Result = Result<crate::ProcResult, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct BIP39Recover {
        pub mnemonic: String,
        pub passphrase: String,
        pub vault_id: VaultId,
        pub record_id: RecordId,
        pub hint: RecordHint,
    }

    impl Message for BIP39Recover {
        type Result = Result<crate::ProcResult, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct Ed25519PublicKey {
        pub vault_id: VaultId,
        pub record_id: RecordId,
    }

    impl Message for Ed25519PublicKey {
        type Result = Result<crate::ProcResult, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug)]
    pub struct Ed25519Sign {
        pub vault_id: VaultId,
        pub record_id: RecordId,
        pub msg: Vec<u8>,
    }

    impl Message for Ed25519Sign {
        type Result = Result<crate::ProcResult, anyhow::Error>;
    }

    #[derive(GuardDebug, Clone, Serialize, Deserialize)]
    pub enum SLIP10DeriveInput {
        /// Note that BIP39 seeds are allowed to be used as SLIP10 seeds
        Seed(Location),
        Key(Location),
    }
}

/// Functional macro to remove boilerplate code for the implementation
/// of the [`SecureActor`].
/// TODO Make receiver type pass as argument.
macro_rules! impl_handler {
    ($mty:ty, $rty:ty, ($sid:ident,$mid:ident, $ctx:ident), $($body:tt)*) => {
        impl Handler<$mty> for SecureClient
        {
            type Result = $rty;
            fn handle(&mut $sid, $mid: $mty, $ctx: &mut Self::Context) -> Self::Result {
                $($body)*
            }
        }
    };

    ($mty:ty, $rty:ty, $($body:tt)*) => {
        impl_handler!($mty, $rty, (self,msg,ctx), $($body)*);
    }
}

#[cfg(test)]
pub mod testing {

    use super::*;
    use crate::Location;

    /// INSECURE MESSAGE
    /// MAY ONLY BE USED IN TESTING CONFIGURATIONS
    ///
    /// Reads data from the vault
    pub struct ReadFromVault {
        pub location: Location,
    }

    impl Message for ReadFromVault {
        type Result = Result<Vec<u8>, anyhow::Error>;
    }

    impl_handler!(ReadFromVault, Result<Vec<u8>, anyhow::Error>, (self, msg, _ctx), {
        let (vid, rid) = self.resolve_location(msg.location);

        if let Some(key) = self.keystore.get_key(vid) {
            let mut data = Vec::new();

            self.db
                .get_guard(&key, vid, rid, |guarded_data| {
                    let guarded_data = guarded_data.borrow();
                    data.extend_from_slice(&*guarded_data);

                    Ok(())
                })
                .map_err(|e| anyhow::anyhow!(e))?;
            self.keystore.insert_key(vid, key);

            return Ok(data);
        }

        Err(anyhow::anyhow!(VaultError::AccessError))
    });
}

impl Actor for SecureClient {
    type Context = Context<Self>;
}

impl Supervised for SecureClient {}

impl_handler!(messages::Terminate, (), (self, _msg, ctx), {
    ctx.stop();
});

impl_handler!(messages::ClearCache, Result<(), anyhow::Error>, (self, _msg, _ctx), {
    self.clear_cache();
    self.keystore.clear_keys();
    self.db.clear().map_err(|e| anyhow::anyhow!(e))
});

impl_handler!(messages::CreateVault, (), (self, msg, _ctx), {
    let (vault_id, _) = self.resolve_location(msg.location);

    let key = self.keystore.create_key(vault_id);
    self.db.init_vault(&key, vault_id).unwrap(); // potentially produces an error
});

impl_handler!(messages::CheckRecord, bool, (self, msg, _ctx), {
    let (vault_id, record_id) = self.resolve_location(msg.location);

    return match self.keystore.get_key(vault_id) {
        Some(key) => {
            self.keystore.insert_key(vault_id, key.clone());
            self.db.contains_record(&key, vault_id, record_id)
        }
        None => false,
    };
});

impl_handler!(messages::WriteToVault, Result<(), anyhow::Error>, (self, msg, _ctx), {
    let (vault_id, record_id) = self.resolve_location(msg.location);

    return match self.keystore.get_key(vault_id) {
        Some(key) => {
            self.keystore.insert_key(vault_id, key.clone());
            self.db.write(&key, vault_id, record_id, &msg.payload, msg.hint).map_err(|e| anyhow::anyhow!(e))
        }
        None => {
            Err(anyhow::anyhow!(VaultError::NotExisting))
        }
    }
});

impl_handler!(messages::RevokeData, Result<(), anyhow::Error>, (self, msg, _ctx), {
    let (vault_id, record_id) = self.resolve_location(msg.location);

    return match self.keystore.get_key(vault_id) {
        Some(key) => {
            self.keystore.insert_key(vault_id, key.clone());
            self.db.revoke_record(&key, vault_id, record_id).map_err(|e| anyhow::anyhow!(e))
        }
        None => {
            Err(anyhow::anyhow!(VaultError::RevokationError))
        }
    }
});

impl_handler!(messages::GarbageCollect, Result<(), anyhow::Error>, (self, msg, _ctx), {
    let (vault_id, _) = self.resolve_location(msg.location);

    return match self.keystore.get_key(vault_id) {
        Some(key) => {
            self.keystore.insert_key(vault_id, key.clone());
            self.db.garbage_collect_vault(&key, vault_id).map_err(|e| anyhow::anyhow!(e))
        }
        None => {
            Err(anyhow::anyhow!(VaultError::GargabeCollectError))
        }
    }
});

impl_handler!(
    messages::ListIds,
    Result<Vec<(RecordId, RecordHint)>, anyhow::Error>,
    (self, msg, _ctx),
    {
        let vault_id = self.derive_vault_id(msg.vault_path);

        match self.keystore.get_key(vault_id) {
            Some(key) => {
                self.keystore.insert_key(vault_id, key.clone());
                Ok(self.db.list_hints_and_ids(&key, vault_id))
            }
            None => Err(anyhow::anyhow!(VaultError::ListError)),
        }
    }
);

impl_handler!(messages::ReloadData, (), (self, msg, _ctx), {
    let (keystore, state, store) = *msg.data;
    let vids = keystore.keys().copied().collect::<HashSet<VaultId>>();
    self.keystore.rebuild_keystore(keystore);
    self.db = state;
    self.rebuild_cache(self.client_id, vids, store);
});

impl_handler!(messages::CheckVault, Result<(), anyhow::Error>, (self, msg, _ctx), {
    let vid = self.derive_vault_id(msg.vault_path);
    self.vault_exist(vid).ok_or(anyhow::anyhow!(VaultError::NotExisting)).map(|_|())
});

impl_handler!(messages::WriteToStore, Result<(), anyhow::Error>, (self, msg, _ctx), {
    let (vault_id, _) = self.resolve_location(msg.location);
    self.write_to_store(vault_id.into(), msg.payload, msg.lifetime);

    Ok(())
});

impl_handler!(
    messages::ReadFromStore,
    Result<Vec<u8>, anyhow::Error>,
    (self, msg, _ctx),
    {
        let (vault_id, _) = self.resolve_location(msg.location);

        match self.read_from_store(vault_id.into()) {
            Some(data) => Ok(data),
            None => Err(anyhow::anyhow!(VaultError::NotExisting)), // semantically wrong, use store error
        }
    }
);

impl_handler!( messages::DeleteFromStore, Result <(), anyhow::Error>, (self, msg, _ctx), {
        let (vault_id, _) = self.resolve_location(msg.location);
        self.store_delete_item(vault_id.into());

        Ok(())
});

impl_handler!(
    messages::GetData,
    Result<
        Box<(
            HashMap<VaultId, Key<internals::Provider>>,
            DbView<internals::Provider>,
            Store
        )>,
        anyhow::Error,
    >,
    (self, _msg, _ctx),
    {
        let keystore = self.keystore.get_data();
        let dbview = self.db.clone();
        let store = self.store.clone();

        Ok(Box::from((keystore, dbview, store)))
    }
);

// ----
// impl for procedures
// ---

/// Intermediate handler for executing procedures
/// will be replace by upcoming `procedures api`
impl Handler<CallProcedure> for SecureClient {
    type Result = Result<procedures::ProcResult, anyhow::Error>;

    fn handle(&mut self, msg: CallProcedure, ctx: &mut Self::Context) -> Self::Result {
        // // TODO move
        use procedures::*;

        // // shifted from interface, that passes the procedure to here
        let procedure = msg.proc;
        match procedure {
            Procedure::SLIP10Generate {
                output,
                hint,
                size_bytes,
            } => {
                let (vault_id, record_id) = self.resolve_location(output);

                <Self as Handler<SLIP10Generate>>::handle(
                    self,
                    SLIP10Generate {
                        vault_id,
                        record_id,
                        hint,
                        size_bytes: size_bytes.unwrap_or(64),
                    },
                    ctx,
                )
            }
            Procedure::SLIP10Derive {
                chain,
                input,
                output,
                hint,
            } => match input {
                SLIP10DeriveInput::Key(parent) => {
                    let (parent_vault_id, parent_record_id) = self.resolve_location(parent);

                    let (child_vault_id, child_record_id) = self.resolve_location(output);
                    if self.vault_exist(child_vault_id).is_none() {
                        self.add_new_vault(child_vault_id);
                    }

                    <Self as Handler<SLIP10DeriveFromKey>>::handle(
                        self,
                        SLIP10DeriveFromKey {
                            chain,
                            hint,
                            parent_vault_id,
                            parent_record_id,
                            child_vault_id,
                            child_record_id,
                        },
                        ctx,
                    )
                }
                SLIP10DeriveInput::Seed(seed) => {
                    let (seed_vault_id, seed_record_id) = self.resolve_location(seed);

                    let (key_vault_id, key_record_id) = self.resolve_location(output);
                    if self.vault_exist(key_vault_id).is_none() {
                        self.add_new_vault(key_vault_id);
                    }

                    <Self as Handler<SLIP10DeriveFromSeed>>::handle(
                        self,
                        SLIP10DeriveFromSeed {
                            chain,
                            hint,
                            seed_vault_id,
                            seed_record_id,
                            key_vault_id,
                            key_record_id,
                        },
                        ctx,
                    )
                }
            },

            Procedure::BIP39Recover {
                mnemonic,
                passphrase,
                output,
                hint,
            } => {
                let (vault_id, record_id) = self.resolve_location(output);

                <Self as Handler<BIP39Recover>>::handle(
                    self,
                    BIP39Recover {
                        mnemonic,
                        passphrase: passphrase.unwrap_or_else(|| "".into()),
                        vault_id,
                        record_id,
                        hint,
                    },
                    ctx,
                )
            }

            Procedure::BIP39Generate {
                passphrase,
                output,
                hint,
            } => {
                let (vault_id, record_id) = self.resolve_location(output);

                <Self as Handler<BIP39Generate>>::handle(
                    self,
                    BIP39Generate {
                        passphrase: passphrase.unwrap_or_else(|| "".into()),
                        vault_id,
                        record_id,
                        hint,
                    },
                    ctx,
                )
            }

            Procedure::BIP39MnemonicSentence { seed: _ } => {
                unimplemented!()
            }

            Procedure::Ed25519PublicKey { private_key } => {
                let (vault_id, record_id) = self.resolve_location(private_key);

                <Self as Handler<Ed25519PublicKey>>::handle(self, Ed25519PublicKey { vault_id, record_id }, ctx)
            }
            Procedure::Ed25519Sign { private_key, msg } => {
                let (vault_id, record_id) = self.resolve_location(private_key);

                <Self as Handler<Ed25519Sign>>::handle(
                    self,
                    Ed25519Sign {
                        vault_id,
                        record_id,
                        msg,
                    },
                    ctx,
                )
            }
        }
    }
}

impl_handler!(
procedures::SLIP10Generate, Result<crate::ProcResult, anyhow::Error>, (self, msg, _ctx), {

    let key = if !self.keystore.vault_exists(msg.vault_id) {
        let key = self.keystore.create_key(msg.vault_id);
        self.db.init_vault(&key, msg.vault_id)?;
        key
    } else {
        self.keystore.get_key(msg.vault_id).unwrap()
    };

    self.keystore.insert_key(msg.vault_id, key.clone());

    let mut seed = vec![0u8; msg.size_bytes];
    fill(&mut seed).map_err(|e| anyhow::anyhow!(e))?;

    match self.db.write(&key, msg.vault_id, msg.record_id,&seed, msg.hint).map_err(|e| anyhow::anyhow!(e)) {
        Ok(_) => {
            Ok(crate::ProcResult::SLIP10Generate(StatusMessage::OK))
        },
        Err(e) => Err(anyhow::anyhow!(e))
    }
});

impl_handler!(procedures::SLIP10DeriveFromSeed, Result<crate::ProcResult, anyhow::Error>, (self, msg, _ctx), {
    match self.keystore.get_key(msg.seed_vault_id) {
        Some(seed_key) => {
            self.keystore.insert_key(msg.seed_vault_id, seed_key.clone());
            let dk_key = if !self.keystore.vault_exists(msg.key_vault_id) {
                let key = self.keystore.create_key(msg.key_vault_id);
                self.db.init_vault(&key, msg.key_vault_id).map_err(|e| anyhow::anyhow!(e))?;
                key

            } else {
                self.keystore.get_key(msg.key_vault_id).ok_or_else(||
                    Err::<crate::ProcResult, anyhow::Error>(anyhow::anyhow!(crate::Error::KeyStoreError("".into())))
                ).unwrap()
            };

            self.keystore.insert_key(msg.key_vault_id, dk_key.clone());

            // FIXME if you see this fix here, that a single-threaded mutable reference
            // is being passed into the closure to obtain the result of the pro-
            // cedure calculation, you should consider rethinking this approach.

            let result = Rc::new(Cell::default());

            match self.db.exec_proc(&seed_key, msg.seed_vault_id, msg.seed_record_id, &dk_key, msg.key_vault_id, msg.key_record_id, msg.hint, |gdata| {
                let dk = Seed::from_bytes(&gdata.borrow())
                    .derive(Curve::Ed25519, &msg.chain).map_err(|e| anyhow::anyhow!(e)).unwrap();
                let data : Vec<u8> = dk.into();

                // was formerly sent to the client
                result.set(dk.chain_code());

                Ok(data)
            }) {
                Ok(_) => {
                    let result = result.get();
                    Ok(ProcResult::SLIP10Derive(ResultMessage::Ok(result)))
                }
                Err(e) => {
                    Err(anyhow::anyhow!(e))
                }
            }
        }

        None => {
            Err(anyhow::anyhow!(VaultError::NotExisting))
        }
    }
});

impl_handler!( procedures::SLIP10DeriveFromKey,Result<crate::ProcResult, anyhow::Error>, (self, msg, _ctx),{
    use std::{rc::Rc, cell::Cell};

    match self.keystore.get_key(msg.parent_vault_id) {
        Some(parent_key) => {
            self.keystore.insert_key(msg.parent_vault_id, parent_key.clone());
            let child_key = if !self.keystore.vault_exists(msg.child_vault_id) {
                let key = self.keystore.create_key(msg.child_vault_id);
                self.db.init_vault(&key, msg.child_vault_id).unwrap();

                key
            } else {
                self.keystore.get_key(msg.child_vault_id).unwrap()
            };

            self.keystore.insert_key(msg.child_vault_id, child_key.clone());

            let result = Rc::new(Cell::default());

            match self.db.exec_proc(&parent_key, msg.parent_vault_id, msg.parent_record_id, &child_key, msg.child_vault_id, msg.child_record_id, msg.hint, |parent | {
                        let parent = slip10::Key::try_from(&*parent.borrow()).unwrap();
                        let dk = parent.derive(&msg.chain).unwrap();

                        let data: Vec<u8> = dk.into();

                        result.set(dk.chain_code());

                    Ok(data)
            }) {
                Ok(_) => {
                    let result = result.get();
                    Ok(ProcResult::SLIP10Derive(ResultMessage::Ok(result)))
                },
                Err(e) => {
                    Err(anyhow::anyhow!(e))
                }
            }
        }
        None => {
            Err(anyhow::anyhow!(VaultError::AccessError))
        }
    }

});

impl_handler!(procedures::BIP39Generate, Result<crate::ProcResult, anyhow::Error>, (self, msg, _ctx), {
            let mut entropy = [0u8; 32];
            if let Err(e) =  fill(&mut entropy) {
                return Err(anyhow::anyhow!(e))
            }

            let mnemonic = match bip39::wordlist::encode(
                &entropy,
                &bip39::wordlist::ENGLISH, // TODO: make this user configurable
            ) {
                Ok(encoded) => encoded,
                Err(e) => { return Err(anyhow::anyhow!(format!("{:?}", e))); }
            };

            let mut seed = [0u8; 64];
            bip39::mnemonic_to_seed(&mnemonic, &msg.passphrase, &mut seed);

            let key = if !self.keystore.vault_exists(msg.vault_id) {
                let k = self.keystore.create_key(msg.vault_id);

                if let Err(e) = self.db.init_vault(&k, msg.vault_id) {
                    return Err(anyhow::anyhow!(e))
                };

                k
            } else {

                match self.keystore.get_key(msg.vault_id) {
                    Some(k) => k,
                    None => { return Err(anyhow::anyhow!(VaultError::NotExisting)); }
                }
            };

            self.keystore.insert_key(msg.vault_id, key.clone());

            // TODO: also store the mnemonic to be able to export it in the
            // BIP39MnemonicSentence message
            match self.db.write(&key, msg.vault_id, msg.record_id, &seed, msg.hint) {
                    Ok(_) => Ok(ProcResult::BIP39Generate(ResultMessage::OK)),
                    Err(e) => Err(anyhow::anyhow!(e))
            }


});

impl_handler!(procedures::BIP39Recover, Result<crate::ProcResult, anyhow::Error>, (self, msg, _ctx), {

        let key = if !self.keystore.vault_exists(msg.vault_id) {
            let k = self.keystore.create_key(msg.vault_id);
            if let Err(e) = self.db.init_vault(&k, msg.vault_id) {
               return Err(anyhow::anyhow!(e))
            };

            k
        } else {
            match self.keystore.get_key(msg.vault_id) {
                Some(key) => key,
                None => { return Err(anyhow::anyhow!(VaultError::NotExisting)); }
            }
        };
            self.keystore.insert_key(msg.vault_id, key.clone());

            let mut seed = [0u8; 64];
            bip39::mnemonic_to_seed(&msg.mnemonic, &msg.passphrase, &mut seed);

            // TODO: also store the mnemonic to be able to export it in the
            // BIP39MnemonicSentence message
            if let Err(e) = self.db.write(&key, msg.vault_id, msg.record_id, &seed, msg.hint) {
                return Err(anyhow::anyhow!(e))
            };


    Ok(ProcResult::BIP39Recover(ResultMessage::OK))
});

impl_handler!(procedures::Ed25519PublicKey, Result<crate::ProcResult, anyhow::Error>, (self, msg, _ctx), {
    use std::{rc::Rc, cell::Cell};
    if let Some(key) = self.keystore.get_key(msg.vault_id) {
        self.keystore.insert_key(msg.vault_id, key.clone());
        let result = Rc::new(Cell::default());

        match self.db
            .get_guard(&key, msg.vault_id, msg.record_id, |data| {
                let raw = data.borrow();
                let mut raw = (*raw).to_vec();

                if raw.len() < 32 {

                    // the client actor will interupt the control flow
                    // but could this be an option to return an error
                    return Err(engine::Error::CryptoError(
                        crypto::Error::BufferSize {has : raw.len(), needs : 32, name: "data buffer" }));

                }
                raw.truncate(32);
                let mut bs = [0; 32];
                bs.copy_from_slice(&raw);

                let sk = match ed25519::SecretKey::from_le_bytes(bs) {
                    Ok(result) => result,
                    Err(_e) => {return Err(engine::Error::CryptoError(
                        crypto::Error::ConvertError { from : "Slice of Bytes", to : "ed25519 SecretKey From LE bytes"}
                    ));}
                };
                let pk = sk.public_key();

                // send to client this result
                result.set(pk.to_compressed_bytes());

                Ok(())
            }) {
                Ok(_) => {},
                Err(e) => {return Err(anyhow::anyhow!(e));}
            }

            let result = result.get();

            Ok(ProcResult::Ed25519PublicKey(ResultMessage::Ok(result)))

    } else {
        Err(anyhow::anyhow!(VaultError::AccessError))
    }

});

impl_handler!(procedures::Ed25519Sign, Result <crate::ProcResult, anyhow::Error>, (self, msg, _ctx), {
    // TODO move
    use std::{rc::Rc, cell::Cell};

    if let Some(pkey) = self.keystore.get_key(msg.vault_id) {
            self.keystore.insert_key(msg.vault_id, pkey.clone());

            let result = Rc::new(Cell::new([0u8; 64]));

            match self.db
                .get_guard(&pkey, msg.vault_id, msg.record_id, |data| {
                    let raw = data.borrow();
                    let mut raw = (*raw).to_vec();

                    if raw.len() < 32 {

                        return Err(engine::Error::CryptoError(
                            crypto::Error::BufferSize {has : raw.len(),needs : 32, name: "data buffer" }));
                    }
                    raw.truncate(32);
                    let mut bs = [0; 32];
                    bs.copy_from_slice(&raw);
                    let sk = match ed25519::SecretKey::from_le_bytes(bs) {
                        Ok(result) => result,
                        Err(_e) => {return Err(engine::Error::CryptoError(
                            crypto::Error::ConvertError { from : "Slice of Bytes", to : "ed25519 SecretKey From LE bytes"}
                        ));}
                    };

                    let sig = sk.sign(&msg.msg);
                    result.set(sig.to_bytes());

                    Ok(())
                }) {
                    Ok(_) => {},
                    Err(e) => {return Err(anyhow::anyhow!(e))}
                };

                let result = result.get();
                Ok(ProcResult::Ed25519Sign(ResultMessage::Ok(result)))
        } else {
            Err(anyhow::anyhow!(VaultError::AccessError))
        }

});
