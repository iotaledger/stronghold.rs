// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
use std::{
    error::Error,
    sync::{Arc, RwLock},
};

use engine::{
    new_runtime::memories::buffer::Buffer,
    vault::{view::Record, BoxProvider, ClientId, DbView, RecordHint, VaultId},
};

use crate::{
    derive_vault_id,
    procedures::{
        FatalProcedureError, Procedure, ProcedureError, ProcedureOutput, Products, Runner, StrongholdProcedure,
    },
    ClientError, ClientVault, KeyStore, Location, Provider, RecordError, Store,
};

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
    /// Returns an [`Arc`] of  [`Self`] to be shared in concurrent setups
    ///
    /// # Example
    /// ```no_run
    /// ```
    fn atomic_ref(&self) -> Client {
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
    pub fn vault(&mut self, vault_path: Location) -> ClientVault {
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
    pub async fn record_exists(&mut self, location: Location) -> Result<bool, ClientError> {
        let (vault_id, record_id) = location.resolve();
        let mut keystore = self.keystore.try_write().map_err(|_| ClientError::LockAcquireFailed)?;
        let result = match keystore.take_key(vault_id) {
            Some(key) => {
                let mut db = self.db.try_write().map_err(|_| ClientError::LockAcquireFailed)?;

                let res = db.contains_record(&key, vault_id, record_id);
                keystore.insert_key(vault_id, key);
                res
            }
            None => false,
        };
        Ok(result)
    }

    /// Returns the [`ClientId`] of the client
    ///
    /// # Example
    /// ```
    /// ```
    pub async fn id(&self) -> &ClientId {
        &self.id
    }

    /// Writes all the changes into the snapshot
    ///
    /// # Example
    /// ```
    /// ```
    pub async fn update<S>(&self, snapshot: S) -> Result<(), Box<dyn Error>> {
        todo!()
    }

    /// Executes a cryptographic [`Procedure`] and returns its output.
    /// A cryptographic [`Procedure`] is the main operation on secrets.
    ///
    /// # Example
    /// ```no_run
    /// ```
    pub async fn execute_procedure<P>(&mut self, procedure: P) -> Result<P::Output, ProcedureError>
    where
        P: Procedure + Into<StrongholdProcedure>,
    {
        let res = self.execure_procedure_chained(vec![procedure.into()]).await;
        let mapped = res.map(|mut vec| vec.pop().unwrap().try_into().ok().unwrap())?;
        Ok(mapped)
    }

    /// Executes a list of cryptographic [`Procedures`] sequentially and returns a collected output
    ///
    /// # Example
    /// ```no_run
    /// ```
    pub async fn execure_procedure_chained(
        &mut self,
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
