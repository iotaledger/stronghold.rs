// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
use std::{
    error::Error,
    sync::{Arc, RwLock},
};

use engine::{
    new_runtime::memories::buffer::Buffer,
    vault::{view::Record, BoxProvider, ClientId, DbView, RecordHint, RecordId, VaultId},
};

use crate::{
    derive_vault_id,
    procedures::{
        FatalProcedureError, Procedure, ProcedureError, ProcedureOutput, Products, Runner, StrongholdProcedure,
    },
    sync::{self, ClientRef, ClientRefMut, MergePolicy, SyncClientsConfig},
    ClientError, ClientState, ClientVault, KeyStore, Location, Provider, RecordError, Store,
};

use super::snapshot;

pub struct Client {
    // A keystore
    pub(crate) keystore: Arc<RwLock<KeyStore<Provider>>>,

    // A view on the vault entries
    pub(crate) db: Arc<RwLock<DbView<Provider>>>,

    // The id of this client
    pub id: ClientId,

    // Contains the Record Ids for the most recent Record in each vault.
    pub store: Store,
}

impl Default for Client {
    fn default() -> Self {
        Self {
            keystore: Arc::new(RwLock::new(KeyStore::default())),
            db: Arc::new(RwLock::new(DbView::new())),
            id: ClientId::default(),
            store: Store::default(),
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {}
}

impl Client {
    /// Returns [`Self`] with atomic references to the same client to be shared in concurrent setups
    ///
    /// # Example
    /// ```no_run
    /// ```
    pub(crate) fn atomic_ref(&self) -> Client {
        Self {
            keystore: self.keystore.clone(),
            db: self.db.clone(),
            id: self.id,
            store: self.store.atomic_ref(),
        }
    }

    /// Returns an atomic reference to the [`Store`]
    ///
    /// # Example
    /// ```
    /// ```
    pub async fn store(&self) -> Store {
        self.store.atomic_ref()
    }

    /// Returns a [`Vault`] according to path
    ///
    /// # Example
    /// ```
    /// ```
    pub fn vault(&self, vault_path: Location) -> ClientVault {
        let (vault_id, _) = vault_path.resolve();

        ClientVault {
            client: self.atomic_ref(),
            id: vault_id,
        }
    }

    /// Returns `true`, if a vault exists
    ///
    /// # Example
    /// ```
    /// ```
    pub async fn vault_exists<P>(&self, vault_path: P) -> Result<bool, ClientError>
    where
        P: AsRef<Vec<u8>>,
    {
        let vault_id = derive_vault_id(vault_path);
        let keystore = self.keystore.try_read().map_err(|_| ClientError::LockAcquireFailed)?;

        Ok(keystore.vault_exists(vault_id))
    }

    /// Returns Ok, if the record exists
    ///
    /// # Example
    /// ```
    /// ```
    pub async fn record_exists(&self, location: Location) -> Result<bool, ClientError> {
        let (vault_id, record_id) = location.resolve();
        let db = self.db.try_read().map_err(|_| ClientError::LockAcquireFailed)?;
        let contains_record = db.contains_record(vault_id, record_id);
        Ok(contains_record)
    }

    /// Synchronize two vaults of the client so that records are copied from `source` to `target`.
    /// If `select_records` is `Some` only the specified records are copied, else a full sync
    /// is performed. If a record already exists at the target, the [`MergePolicy`] applies.
    ///
    /// # Example
    /// ```
    /// ```
    pub fn sync_vaults(
        &self,
        source: VaultId,
        target: VaultId,
        select_records: Option<Vec<RecordId>>,
        merge_policy: MergePolicy,
    ) -> Result<(), ClientError> {
        let select_vaults = vec![source];
        let map_vaults = [(source, target)].into();
        let select_records = select_records.map(|vec| [(source, vec)].into()).unwrap_or_default();
        let config = SyncClientsConfig {
            select_vaults: Some(select_vaults),
            select_records,
            map_vaults,
            merge_policy,
        };
        let state = ClientRef::try_from(self)?;

        let hierarchy = state.get_hierarchy(config.select_vaults.clone());
        let diff = state.get_diff(hierarchy, &config);
        let exported = state.export_entries(diff);

        drop(state);
        let mut state_mut = ClientRefMut::try_from(self)?;
        state_mut.import_own_records(exported, config.map_vaults);
        Ok(())
    }

    /// Synchronize the client with another one so that records are copied from `other` to `self`.
    ///
    /// # Example
    /// ```
    /// ```
    pub fn sync_with(&self, other: &Self, config: SyncClientsConfig) -> Result<(), ClientError> {
        let self_state = ClientRef::try_from(self)?;
        let other_state = ClientRef::try_from(other)?;

        let hierarchy = other_state.get_hierarchy(config.select_vaults.clone());
        let diff = self_state.get_diff(hierarchy, &config);
        let exported = other_state.export_entries(diff);

        drop(self_state);
        let mut self_state_mut = ClientRefMut::try_from(self)?;
        self_state_mut.import_records(exported, &other_state.keystore, &config);
        Ok(())
    }

    /// Returns the [`ClientId`] of the client
    ///
    /// # Example
    /// ```
    /// ```
    pub fn id(&self) -> &ClientId {
        &self.id
    }

    /// Loads the state of [`Self`] from a [`ClientState`]. Replaces all previous data.
    ///
    /// # Example
    /// ```
    /// ```
    pub(crate) async fn load(&self, state: ClientState, id: ClientId) -> Result<(), ClientError> {
        let (keys, db, st) = state;

        // reload keystore
        let mut keystore = self.keystore.try_write().map_err(|_| ClientError::LockAcquireFailed)?;
        let mut new_keystore = KeyStore::<Provider>::default();
        new_keystore
            .rebuild_keystore(keys)
            .map_err(|e| ClientError::Inner(e.to_string()))?;

        *keystore = new_keystore;
        drop(keystore);

        // reload db
        let mut view = self.db.try_write().map_err(|_| ClientError::LockAcquireFailed)?;
        *view = db;
        drop(view);

        // reload store
        let mut store = self
            .store
            .cache
            .try_write()
            .map_err(|_| ClientError::LockAcquireFailed)?;
        *store = st;
        drop(store);

        Ok(())
    }

    /// Executes a cryptographic [`Procedure`] and returns its output.
    /// A cryptographic [`Procedure`] is the main operation on secrets.
    ///
    /// # Example
    /// ```no_run
    /// ```
    pub async fn execute_procedure<P>(&self, procedure: P) -> Result<P::Output, ProcedureError>
    where
        P: Procedure + Into<StrongholdProcedure>,
    {
        let res = self.execute_procedure_chained(vec![procedure.into()]).await;
        let mapped = res.map(|mut vec| vec.pop().unwrap().try_into().ok().unwrap())?;
        Ok(mapped)
    }

    /// Executes a list of cryptographic [`Procedures`] sequentially and returns a collected output
    ///
    /// # Example
    /// ```no_run
    /// ```
    pub async fn execute_procedure_chained(
        &self,
        procedures: Vec<StrongholdProcedure>,
    ) -> core::result::Result<Vec<ProcedureOutput>, ProcedureError> {
        let mut out = Vec::new();
        let mut log = Vec::new();
        // Execute the procedures sequentially.
        for proc in procedures {
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

// TODO: Compatibility to former structure
