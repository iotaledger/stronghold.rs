// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Secure Actor module
//!
//! The secure actor runs as service, isolates contained data, and synchronizes
//! across multiple accesses.

#![allow(clippy::type_complexity)]

pub use crate::{
    actors::{GetSnapshot, Registry},
    internals::Provider,
    state::{key_store::KeyStore, secure::SecureClient, snapshot::Snapshot},
    utils::StatusMessage,
    ResultMessage,
};
use crate::{
    internals,
    procedures::{CollectedOutput, Procedure, Runner},
};
use actix::{Actor, ActorContext, Context, Handler, Message, Supervised};

use engine::{
    store::Cache,
    vault::{ClientId, DbView, Key, RecordHint, RecordId, VaultId},
};
use std::collections::HashMap;

/// Store typedef on `engine::store::Cache`
pub type Store = Cache<Vec<u8>, Vec<u8>>;

use stronghold_utils::GuardDebug;
use thiserror::Error as DeriveError;

#[derive(DeriveError, Debug)]
pub enum VaultError {
    #[error("Vault does not exist")]
    NotExisting,

    #[error("Failed to revoke record, vault does not exist")]
    RevocationError,

    #[error("Failed to collect gargabe, vault does not exist")]
    GarbageCollectError,

    #[error("Failed to get list, vault does not exist")]
    ListError,

    #[error("Failed to access Vault")]
    AccessError,
}

#[derive(DeriveError, Debug)]
pub enum StoreError {
    #[error("Unable to read from store")]
    NotExisting,
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
    pub struct CreateVault {
        pub location: Location,
    }

    impl Message for CreateVault {
        type Result = ();
    }

    #[derive(Clone, GuardDebug, Serialize, Deserialize)]
    pub struct WriteToVault {
        pub location: Location,

        pub payload: Vec<u8>,
        pub hint: RecordHint,
    }

    impl Message for WriteToVault {
        type Result = Result<(), anyhow::Error>;
    }

    #[derive(Clone, GuardDebug, Serialize, Deserialize)]
    pub struct RevokeData {
        pub location: Location,
    }

    impl Message for RevokeData {
        type Result = Result<(), anyhow::Error>;
    }

    #[derive(Clone, GuardDebug, Serialize, Deserialize)]
    pub struct GarbageCollect {
        pub location: Location,
    }

    impl Message for GarbageCollect {
        type Result = Result<(), anyhow::Error>;
    }

    #[derive(Clone, GuardDebug, Serialize, Deserialize)]
    pub struct ListIds {
        pub vault_path: Vec<u8>,
    }

    impl Message for ListIds {
        type Result = Result<Vec<(RecordId, RecordHint)>, anyhow::Error>;
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
        type Result = Result<(), anyhow::Error>;
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
        pub location: Location,
        pub payload: Vec<u8>,
        pub lifetime: Option<Duration>,
    }

    impl Message for WriteToStore {
        type Result = Result<(), anyhow::Error>;
    }

    #[derive(Clone, GuardDebug, Serialize, Deserialize)]
    pub struct ReadFromStore {
        pub location: Location,
    }

    impl Message for ReadFromStore {
        type Result = Result<Vec<u8>, anyhow::Error>;
    }

    #[derive(Clone, GuardDebug, Serialize, Deserialize)]
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
        type Result = Result<Vec<u8>, anyhow::Error>;
    }

    impl_handler!(ReadFromVault, Result<Vec<u8>, anyhow::Error>, (self, msg, _ctx), {
        let (vid, rid) = Self::resolve_location(msg.location);

        let key = self.keystore.take_key(vid)?;

        let mut data = Vec::new();
        let res = self.db.get_guard(&key, vid, rid, |guarded_data| {
            let guarded_data = guarded_data.borrow();
            data.extend_from_slice(&*guarded_data);
            Ok(())
        });
        self.keystore.insert_key(vid, key);

        match res {
            Ok(_) => Ok(data),
            Err(e) => Err(anyhow::anyhow!(e)),
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

impl_handler!(messages::ClearCache, Result<(), anyhow::Error>, (self, _msg, _ctx), {
    self.keystore.clear_keys();
    self.db.clear().map_err(|e| anyhow::anyhow!(e))
});

impl_handler!(messages::CreateVault, (), (self, msg, _ctx), {
    let (vault_id, _) = Self::resolve_location(msg.location);

    let key = self.keystore.create_key(vault_id);
    self.db.init_vault(key, vault_id).unwrap(); // potentially produces an error
});

impl_handler!(messages::CheckRecord, bool, (self, msg, _ctx), {
    let (vault_id, record_id) = Self::resolve_location(msg.location);

    return match self.keystore.take_key(vault_id) {
        Ok(key) => {
            let res = self.db.contains_record(&key, vault_id, record_id);
            self.keystore.insert_key(vault_id, key);
            res
        }
        Err(_) => false,
    };
});

impl_handler!(messages::WriteToVault, Result<(), anyhow::Error>, (self, msg, _ctx), {
    let (vault_id, record_id) = Self::resolve_location(msg.location);

    let key = self
        .keystore
        .take_key(vault_id)?;

    let res = self.db.write(&key, vault_id, record_id, &msg.payload, msg.hint);
    self.keystore.insert_key(vault_id, key);
    res.map_err(|e| anyhow::anyhow!(e))
});

impl_handler!(messages::RevokeData, Result<(), anyhow::Error>, (self, msg, _ctx), {
    self.revoke_data(&msg.location)
});

impl_handler!(messages::GarbageCollect, Result<(), anyhow::Error>, (self, msg, _ctx), {
    let (vault_id, _) = Self::resolve_location(msg.location);
    self.garbage_collect(vault_id)
});

impl_handler!(
    messages::ListIds,
    Result<Vec<(RecordId, RecordHint)>, anyhow::Error>,
    (self, msg, _ctx),
    {
        let vault_id = Self::derive_vault_id(msg.vault_path);
        let key = self.keystore.take_key(vault_id)?;

        let list = self.db.list_hints_and_ids(&key, vault_id);
        self.keystore.insert_key(vault_id, key);
        Ok(list)
    }
);

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

impl_handler!(messages::WriteToStore, Result<(), anyhow::Error>, (self, msg, _ctx), {
    let (vault_id, _) = Self::resolve_location(msg.location);
    self.write_to_store(vault_id.into(), msg.payload, msg.lifetime);

    Ok(())
});

impl_handler!(
    messages::ReadFromStore,
    Result<Vec<u8>, anyhow::Error>,
    (self, msg, _ctx),
    {
        let (vault_id, _) = Self::resolve_location(msg.location);

        match self.read_from_store(vault_id.into()) {
            Some(data) => Ok(data),
            None => Err(anyhow::anyhow!(StoreError::NotExisting)),
        }
    }
);

impl_handler!( messages::DeleteFromStore, Result <(), anyhow::Error>, (self, msg, _ctx), {
    let (vault_id, _) = Self::resolve_location(msg.location);
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

impl Handler<Procedure> for SecureClient {
    type Result = Result<CollectedOutput, anyhow::Error>;

    fn handle(&mut self, proc: Procedure, _: &mut Self::Context) -> Self::Result {
        proc.run(self)
    }
}
