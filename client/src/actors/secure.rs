// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Secure Actor module
//!
//! The secure actor runs as service, isolates contained data, and synchronizes
//! across multiple accesses.

#![allow(clippy::type_complexity)]

use crate::procedures::Runner;
pub use crate::{
    internals::Provider,
    procedures::{CollectedOutput, Procedure, ProcedureError},
    state::{key_store::KeyStore, secure::SecureClient, snapshot::Snapshot},
};
use actix::{Actor, ActorContext, Context, Handler, Message, MessageResult, Supervised};

use engine::{
    store::Cache,
    vault::{BoxProvider, ClientId, DbView, Key, RecordHint, RecordId, VaultError as EngineVaultError, VaultId},
};
use std::{collections::HashMap, convert::Infallible};

/// Store typedef on `engine::store::Cache`
pub type Store = Cache<Vec<u8>, Vec<u8>>;

pub type VaultError<E = Infallible> = EngineVaultError<<Provider as BoxProvider>::Error, E>;

use stronghold_utils::GuardDebug;

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
        type Result = Result<(), VaultError>;
    }

    #[derive(Clone, GuardDebug, Serialize, Deserialize)]
    pub struct RevokeData {
        pub location: Location,
    }

    impl Message for RevokeData {
        type Result = Result<(), VaultError>;
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

impl_handler!(messages::CreateVault, (), (self, msg, _ctx), {
    let (vault_id, _) = Self::resolve_location(msg.location);

    let key = self.keystore.create_key(vault_id);
    self.db.init_vault(key, vault_id);
});

impl_handler!(messages::CheckRecord, bool, (self, msg, _ctx), {
    let (vault_id, record_id) = Self::resolve_location(msg.location);

    return match self.keystore.take_key(vault_id) {
        Some(key) => {
            let res = self.db.contains_record(&key, vault_id, record_id);
            self.keystore.insert_key(vault_id, key);
            res
        }
        None => false,
    };
});

impl_handler!(messages::WriteToVault, Result<(), VaultError>, (self, msg, _ctx), {
    let (vault_id, record_id) = Self::resolve_location(msg.location);

    let key = self
        .keystore
        .take_key(vault_id)
        .ok_or(VaultError::VaultNotFound(vault_id))?;

    let res = self.db.write(&key, vault_id, record_id, &msg.payload, msg.hint);
    self.keystore.insert_key(vault_id, key);
    res.map_err(|e| e.into())
});

impl_handler!(messages::RevokeData, Result<(), VaultError>, (self, msg, _ctx), {
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

// ----
// impl for procedures
// ---

impl Handler<Procedure> for SecureClient {
    type Result = Result<CollectedOutput, ProcedureError>;

    fn handle(&mut self, proc: Procedure, _: &mut Self::Context) -> Self::Result {
        proc.run(self)
    }
}
