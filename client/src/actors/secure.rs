// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Secure Actor module
//!
//! The secure actor runs as service, isolates contained data, and synchronizes
//! across multiple accesses.

#![allow(clippy::type_complexity)]

use crate::{
    internals::Provider,
    procedures::{Procedure, ProcedureError, ProcedureOutput, Runner},
    state::secure::SecureClient,
};
use actix::{Actor, ActorContext, Context, Handler, Message, MessageResult, Supervised};
use engine::{
    store::Cache,
    vault::{
        BoxProvider, ClientId, DbView, Key, RecordError as EngineRecordError, RecordHint, RecordId,
        VaultError as EngineVaultError, VaultId,
    },
};

#[cfg(feature = "p2p")]
use engine::runtime::GuardedVec;
#[cfg(feature = "p2p")]
use p2p::{identity::Keypair, AuthenticKeypair, NoiseKeypair, PeerId};
use std::{collections::HashMap, convert::Infallible};
use stronghold_utils::GuardDebug;

/// Store typedef on `engine::store::Cache`
pub type Store = Cache<Vec<u8>, Vec<u8>>;

pub type VaultError<E = Infallible> = EngineVaultError<<Provider as BoxProvider>::Error, E>;
pub type RecordError = EngineRecordError<<Provider as BoxProvider>::Error>;

/// Message types for the [`SecureClient`].
pub mod messages {

    use super::*;
    use crate::{internals, procedures::StrongholdProcedure, Location};
    use serde::{Deserialize, Serialize};
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
    #[derive(Clone, GuardDebug, Serialize, Deserialize)]
    pub struct WriteToVault {
        pub location: Location,

        pub payload: Vec<u8>,
        pub hint: RecordHint,
    }

    impl Message for WriteToVault {
        type Result = Result<(), RecordError>;
    }

    #[derive(Clone, GuardDebug, Serialize, Deserialize)]
    pub struct RevokeData {
        pub location: Location,
    }

    impl Message for RevokeData {
        type Result = Result<(), RecordError>;
    }

    #[derive(Clone, GuardDebug, Serialize, Deserialize)]
    pub struct GarbageCollect {
        pub location: Location,
    }

    impl Message for GarbageCollect {
        type Result = bool;
    }

    #[derive(Clone, GuardDebug, Serialize, Deserialize)]
    pub struct ListIds {
        pub vault_path: Vec<u8>,
    }

    impl Message for ListIds {
        type Result = Vec<(RecordId, RecordHint)>;
    }

    #[derive(Clone, GuardDebug, Serialize, Deserialize)]
    pub struct CheckRecord {
        pub location: Location,
    }

    impl Message for CheckRecord {
        type Result = bool;
    }

    #[derive(Clone, GuardDebug, Serialize, Deserialize)]
    pub struct ClearCache;

    impl Message for ClearCache {
        type Result = ();
    }

    #[derive(Clone, GuardDebug, Serialize, Deserialize)]
    pub struct CheckVault {
        pub vault_path: Vec<u8>,
    }

    impl Message for CheckVault {
        type Result = bool;
    }

    #[derive(Clone, GuardDebug, Serialize, Deserialize)]
    pub struct WriteToStore {
        pub key: Vec<u8>,
        pub payload: Vec<u8>,
        pub lifetime: Option<Duration>,
    }

    impl Message for WriteToStore {
        type Result = Option<Vec<u8>>;
    }

    #[derive(Clone, GuardDebug, Serialize, Deserialize)]
    pub struct ReadFromStore {
        pub key: Vec<u8>,
    }

    impl Message for ReadFromStore {
        type Result = Option<Vec<u8>>;
    }

    #[derive(Clone, GuardDebug, Serialize, Deserialize)]
    pub struct DeleteFromStore {
        pub key: Vec<u8>,
    }

    impl Message for DeleteFromStore {
        type Result = ();
    }

    pub struct GetData {}

    impl Message for GetData {
        type Result = Box<(
            HashMap<VaultId, Key<internals::Provider>>,
            DbView<internals::Provider>,
            Store,
        )>;
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Procedures {
        pub procedures: Vec<StrongholdProcedure>,
    }

    impl Message for Procedures {
        type Result = Result<Vec<ProcedureOutput>, ProcedureError>;
    }

    impl<T: Into<StrongholdProcedure>> From<T> for Procedures {
        fn from(proc: T) -> Self {
            Procedures {
                procedures: vec![proc.into()],
            }
        }
    }
}

#[cfg(feature = "p2p")]
pub mod p2p_messages {

    use crate::Location;

    use super::*;

    // Generate new keypair to use for `StrongholdP2p`.
    pub struct GenerateP2pKeypair {
        pub location: Location,
        pub hint: RecordHint,
    }

    impl Message for GenerateP2pKeypair {
        type Result = Result<(), ProcedureError>;
    }

    pub struct WriteP2pKeypair {
        pub keypair: Keypair,
        pub location: Location,
        pub hint: RecordHint,
    }

    impl Message for WriteP2pKeypair {
        type Result = Result<(), ProcedureError>;
    }

    // Derive a new noise keypair from a stored p2p-keypair.
    // Returns the new keypair and the `PeerId` that is derived from the public
    // key of the stored keypair.
    // **Note**: The keypair differs for each new derivation, the `PeerId`
    // is consistent.
    pub struct DeriveNoiseKeypair {
        pub p2p_keypair: Location,
    }

    impl Message for DeriveNoiseKeypair {
        type Result = Result<(PeerId, AuthenticKeypair), ProcedureError>;
    }
}

/// Functional macro to remove boilerplate code for the implementation
/// of the [`SecureClient`].
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
    use engine::vault::{RecordError, VaultError};
    use serde::{Deserialize, Serialize};

    /// INSECURE MESSAGE
    /// MAY ONLY BE USED IN TESTING CONFIGURATIONS
    ///
    /// Reads data from the vault
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ReadFromVault {
        pub location: Location,
    }

    impl Message for ReadFromVault {
        type Result = Option<Vec<u8>>;
    }

    impl_handler!(ReadFromVault, Option<Vec<u8>>, (self, msg, _ctx), {
        let (vid, rid) = Self::resolve_location(msg.location);

        let key = self.keystore.take_key(vid)?;

        let mut data = Vec::new();
        let res = self.db.get_guard::<(), _>(&key, vid, rid, |guarded_data| {
            let guarded_data = guarded_data.borrow();
            data.extend_from_slice(&*guarded_data);
            Ok(())
        });
        self.keystore.insert_key(vid, key);

        match res {
            Ok(()) => Some(data),
            Err(VaultError::VaultNotFound(_)) | Err(VaultError::Record(RecordError::RecordNotFound(_))) => None,
            Err(VaultError::Record(e)) => panic!("Internal Error: {}", e),
            Err(VaultError::Procedure(_)) => unreachable!(),
        }
    });
}

impl Actor for SecureClient {
    type Context = Context<Self>;
}

impl Supervised for SecureClient {}

impl_handler!(messages::Terminate, (), (self, _msg, ctx), {
    ctx.stop();
});

impl_handler!(messages::ClearCache, (), (self, _msg, _ctx), {
    self.keystore.clear_keys();
    self.db.clear();
});

impl_handler!(messages::CheckRecord, bool, (self, msg, _ctx), {
    let (vault_id, record_id) = Self::resolve_location(msg.location);
    self.db.contains_record(vault_id, record_id)
});

impl_handler!(messages::WriteToVault, Result<(), RecordError>, (self, msg, _ctx), {
    self.write_to_vault(&msg.location, msg.hint, msg.payload)
});

impl_handler!(messages::RevokeData, Result<(), RecordError>, (self, msg, _ctx), {
    self.revoke_data(&msg.location)
});

impl_handler!(messages::GarbageCollect, bool, (self, msg, _ctx), {
    let (vault_id, _) = Self::resolve_location(msg.location);
    self.garbage_collect(vault_id)
});

impl_handler!(messages::ListIds, Vec<(RecordId, RecordHint)>, (self, msg, _ctx), {
    let vault_id = Self::derive_vault_id(msg.vault_path);
    let key = match self.keystore.take_key(vault_id) {
        Some(k) => k,
        None => return Vec::new(),
    };

    let list = self.db.list_hints_and_ids(&key, vault_id);
    self.keystore.insert_key(vault_id, key);
    list
});

impl_handler!(messages::ReloadData, (), (self, msg, _ctx), {
    let (keystore, state, store) = *msg.data;
    self.keystore.rebuild_keystore(keystore);
    self.db = state;
    self.rebuild_cache(self.client_id, store);
});

impl_handler!(messages::CheckVault, bool, (self, msg, _ctx), {
    let vid = Self::derive_vault_id(msg.vault_path);
    self.keystore.vault_exists(vid)
});

impl_handler!(messages::WriteToStore, Option<Vec<u8>>, (self, msg, _ctx), {
    self.write_to_store(msg.key, msg.payload, msg.lifetime)
});

impl_handler!(messages::ReadFromStore, Option<Vec<u8>>, (self, msg, _ctx), {
    self.read_from_store(msg.key)
});

impl_handler!(messages::DeleteFromStore, (), (self, msg, _ctx), {
    self.store_delete_item(msg.key);
});

impl_handler!(
    messages::GetData,
    MessageResult<messages::GetData>,
    (self, _msg, _ctx),
    {
        let keystore = self.keystore.get_data();
        let dbview = self.db.clone();
        let store = self.store.clone();

        MessageResult(Box::from((keystore, dbview, store)))
    }
);

impl Handler<messages::Procedures> for SecureClient {
    type Result = Result<Vec<ProcedureOutput>, ProcedureError>;

    fn handle(&mut self, msg: messages::Procedures, _: &mut Self::Context) -> Self::Result {
        let mut out = Vec::new();
        let mut log = Vec::new();
        // Execute the procedures sequentially.
        for proc in msg.procedures {
            if let Some(output) = proc.output() {
                log.push(output);
            }
            let output = match proc.execute(self) {
                Ok(o) => o,
                Err(e) => {
                    for location in log {
                        let _ = self.revoke_data(&location);
                    }
                    return Err(e);
                }
            };
            out.push(output);
        }
        Ok(out)
    }
}

#[cfg(feature = "p2p")]
impl Handler<p2p_messages::GenerateP2pKeypair> for SecureClient {
    type Result = Result<(), ProcedureError>;

    fn handle(&mut self, msg: p2p_messages::GenerateP2pKeypair, _ctx: &mut Self::Context) -> Self::Result {
        let keypair = Keypair::generate_ed25519();
        let bytes = keypair
            .to_protobuf_encoding()
            .map_err(|e| ProcedureError::Procedure(e.to_string().into()))?;
        self.write_to_vault(&msg.location, msg.hint, bytes)?;
        Ok(())
    }
}

#[cfg(feature = "p2p")]
impl Handler<p2p_messages::WriteP2pKeypair> for SecureClient {
    type Result = Result<(), ProcedureError>;

    fn handle(&mut self, msg: p2p_messages::WriteP2pKeypair, _ctx: &mut Self::Context) -> Self::Result {
        let bytes = msg
            .keypair
            .to_protobuf_encoding()
            .map_err(|e| ProcedureError::Procedure(e.to_string().into()))?;
        self.write_to_vault(&msg.location, msg.hint, bytes)?;
        Ok(())
    }
}

#[cfg(feature = "p2p")]
impl Handler<p2p_messages::DeriveNoiseKeypair> for SecureClient {
    type Result = Result<(PeerId, AuthenticKeypair), ProcedureError>;

    fn handle(&mut self, msg: p2p_messages::DeriveNoiseKeypair, _ctx: &mut Self::Context) -> Self::Result {
        let mut id_keys = None;
        let f = |guard: GuardedVec<u8>| {
            let keys = Keypair::from_protobuf_encoding(&*guard.borrow()).map_err(|e| e.to_string())?;
            let _ = id_keys.insert(keys);
            Ok(())
        };
        self.get_guard(&msg.p2p_keypair, f)?;
        let id_keys = id_keys.unwrap();
        let keypair = NoiseKeypair::new()
            .into_authentic(&id_keys)
            .map_err(|e| ProcedureError::Procedure(e.to_string().into()))?;
        let peer_id = PeerId::from_public_key(&id_keys.public());
        Ok((peer_id, keypair))
    }
}
