// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
use std::{
    collections::HashMap,
    error::Error,
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
};

use engine::{
    new_runtime::memories::buffer::Buffer,
    vault::{view::Record, BoxProvider, ClientId, DbView, Key, RecordHint, RecordId, VaultId},
};

use crate::{
    derive_vault_id,
    procedures::{
        FatalProcedureError, Procedure, ProcedureError, ProcedureOutput, Products, Runner, StrongholdProcedure,
    },
    sync::{KeyProvider, MergePolicy, SyncClients, SyncClientsConfig},
    ClientError, ClientState, ClientVault, KeyStore, Location, Provider, RecordError, SnapshotError, Store,
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
        let keystore = self.keystore.try_read()?;

        Ok(keystore.vault_exists(vault_id))
    }

    /// Returns Ok, if the record exists
    ///
    /// # Example
    /// ```
    /// ```
    pub async fn record_exists(&self, location: Location) -> Result<bool, ClientError> {
        let (vault_id, record_id) = location.resolve();
        let db = self.db.try_read()?;
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
        source_path: Vec<u8>,
        target_path: Vec<u8>,
        select_records: Option<Vec<RecordId>>,
        merge_policy: MergePolicy,
    ) -> Result<(), ClientError> {
        let source = derive_vault_id(source_path);
        let target = derive_vault_id(target_path);
        let select_vaults = vec![source];
        let map_vaults = [(source, target)].into();
        let select_records = select_records.map(|vec| [(source, vec)].into()).unwrap_or_default();
        let mut config = SyncClientsConfig {
            select_vaults: Some(select_vaults),
            select_records,
            map_vaults,
            merge_policy,
        };
        let hierarchy = self.get_hierarchy(config.select_vaults.clone())?;
        let diff = self.get_diff(hierarchy, &config)?;
        let exported = self.export_entries(diff)?;
        let mut db = self.db.try_write()?;
        let mut key_store = self.keystore.try_write()?;

        for (vid, records) in exported {
            let mapped_vid = config.map_vaults.remove(&vid).unwrap_or(vid);
            let old_key = key_store
                .get_key(vid)
                .ok_or_else(|| ClientError::Inner(format!("Missing Key for vault {:?}", vid)))?;
            let new_key = key_store.get_or_insert_key(mapped_vid, Key::random())?;
            db.import_records(&old_key, &new_key, mapped_vid, records)?
        }
        Ok(())
    }

    /// Synchronize the client with another one so that records are copied from `other` to `self`.
    ///
    /// # Example
    /// ```
    /// ```
    pub fn sync_with(&self, other: &Self, config: SyncClientsConfig) -> Result<(), ClientError> {
        let hierarchy = other.get_hierarchy(config.select_vaults.clone())?;
        let diff = self.get_diff(hierarchy, &config)?;
        let exported = other.export_entries(diff)?;

        for (vid, mut records) in exported {
            if let Some(select_vaults) = config.select_vaults.as_ref() {
                if !select_vaults.contains(&vid) {
                    continue;
                }
            }
            if let Some(select_records) = config.select_records.get(&vid) {
                records.retain(|(rid, _)| select_records.contains(rid));
            }
            let mapped_vid = config.map_vaults.get(&vid).copied().unwrap_or(vid);
            let old_key = other
                .keystore
                .try_read()?
                .get_key(vid)
                .ok_or_else(|| ClientError::Inner(format!("Missing Key for vault {:?}", vid)))?;
            let new_key = self
                .keystore
                .try_write()?
                .get_or_insert_key(mapped_vid, Key::random())?;
            self.db
                .try_write()?
                .import_records(&old_key, &new_key, mapped_vid, records)?
        }
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
        let mut keystore = self.keystore.try_write()?;
        let mut new_keystore = KeyStore::<Provider>::default();
        new_keystore
            .rebuild_keystore(keys)
            .map_err(|e| ClientError::Inner(e.to_string()))?;

        *keystore = new_keystore;
        drop(keystore);

        // reload db
        let mut view = self.db.try_write()?;
        *view = db;
        drop(view);

        // reload store
        let mut store = self.store.cache.try_write()?;
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

impl<'a> SyncClients<'a> for Client {
    type Db = RwLockReadGuard<'a, DbView<Provider>>;

    fn get_db(&'a self) -> Result<Self::Db, ClientError> {
        let db = self.db.try_read()?;
        Ok(db)
    }

    fn get_key_provider(&'a self) -> Result<KeyProvider<'a>, ClientError> {
        let ks = self.keystore.try_read()?;
        Ok(KeyProvider::KeyStore(ks))
    }
}

// TODO: Compatibility to former structure
