// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Secure Client Actor State

use crate::{
    actors::{RecordError, VaultError},
    internals,
    procedures::{FatalProcedureError, Products, Runner},
    state::key_store::KeyStore,
    Location,
};
use engine::{
    new_runtime::memories::buffer::Buffer,
    store::Cache,
    vault::{ClientId, DbView, RecordHint, VaultId},
};
use std::time::Duration;

/// Cache type definition
pub type Store = Cache<Vec<u8>, Vec<u8>>;

pub struct SecureClient {
    // A keystore
    pub(crate) keystore: KeyStore,
    // A view on the vault entries
    pub(crate) db: DbView<internals::Provider>,
    // The id of this client
    pub client_id: ClientId,
    // Contains the Record Ids for the most recent Record in each vault.
    pub store: Store,
}

impl SecureClient {
    /// Creates a new Client given a `ClientID` and `ChannelRef<SHResults>`
    pub fn new(client_id: ClientId) -> Self {
        let store = Cache::new();

        Self {
            client_id,
            store,
            keystore: KeyStore::new(),
            db: DbView::new(),
        }
    }

    /// Write unencrypted data to the store.  Returns [`None`] if the key didn't already exist and [`Some(Vec<u8>)`] if
    /// the key was updated.
    pub fn write_to_store(&mut self, key: Vec<u8>, data: Vec<u8>, lifetime: Option<Duration>) -> Option<Vec<u8>> {
        self.store.insert(key, data, lifetime)
    }

    /// Attempts to read the data from the store.  Returns [`Some(Vec<u8>)`] if the key exists and [`None`] if it
    /// doesn't.
    pub fn read_from_store(&mut self, key: Vec<u8>) -> Option<Vec<u8>> {
        self.store.get(&key).map(|v| v.to_vec())
    }

    /// Deletes an item from the store by the given key.
    pub fn store_delete_item(&mut self, key: Vec<u8>) {
        self.store.remove(&key);
    }

    /// Checks to see if the key exists in the store.
    pub fn store_key_exists(&mut self, key: Vec<u8>) -> bool {
        self.store.contains_key(&key)
    }

    /// Sets the client id to swap from one client to another.
    pub fn set_client_id(&mut self, client_id: ClientId) {
        self.client_id = client_id
    }

    /// Rebuilds the cache using the parameters.
    pub fn rebuild_cache(&mut self, id: ClientId, store: Store) {
        self.client_id = id;
        self.store = store;
    }

    /// Gets the client string.
    pub fn get_client_str(&self) -> String {
        self.client_id.into()
    }
}

impl Runner for SecureClient {
    fn get_guard<F, T>(&mut self, location: &Location, f: F) -> Result<T, VaultError<FatalProcedureError>>
    where
        F: FnOnce(Buffer<u8>) -> Result<T, FatalProcedureError>,
    {
        let (vault_id, record_id) = location.resolve();
        let key = self
            .keystore
            .take_key(vault_id)
            .ok_or(VaultError::VaultNotFound(vault_id))?;

        let mut ret = None;
        let execute_procedure = |guard: Buffer<u8>| {
            ret = Some(f(guard)?);
            Ok(())
        };
        let res = self.db.get_guard(&key, vault_id, record_id, execute_procedure);
        self.keystore.entry_or_insert_key(vault_id, key);

        match res {
            Ok(()) => Ok(ret.unwrap()),
            Err(e) => Err(e),
        }
    }

    fn exec_proc<F, T>(
        &mut self,
        location0: &Location,
        location1: &Location,
        hint: RecordHint,
        f: F,
    ) -> Result<T, VaultError<FatalProcedureError>>
    where
        F: FnOnce(Buffer<u8>) -> Result<Products<T>, FatalProcedureError>,
    {
        let (vid0, rid0) = location0.resolve();
        let (vid1, rid1) = location1.resolve();

        let key0 = self.keystore.take_key(vid0).ok_or(VaultError::VaultNotFound(vid0))?;

        let mut ret = None;
        let execute_procedure = |guard: Buffer<u8>| {
            let Products { output: plain, secret } = f(guard)?;
            ret = Some(plain);
            Ok(secret)
        };

        let res;
        if vid0 == vid1 {
            res = self
                .db
                .exec_proc(&key0, vid0, rid0, &key0, vid1, rid1, hint, execute_procedure);
        } else {
            if !self.keystore.vault_exists(vid1) {
                let key1 = self.keystore.create_key(vid1);
                self.db.init_vault(key1, vid1);
            }
            let key1 = self.keystore.take_key(vid1).unwrap();
            res = self
                .db
                .exec_proc(&key0, vid0, rid0, &key1, vid1, rid1, hint, execute_procedure);
            self.keystore.entry_or_insert_key(vid1, key1);
        }

        self.keystore.entry_or_insert_key(vid0, key0);

        match res {
            Ok(()) => Ok(ret.unwrap()),
            Err(e) => Err(e),
        }
    }

    fn write_to_vault(&mut self, location: &Location, hint: RecordHint, value: Vec<u8>) -> Result<(), RecordError> {
        let (vault_id, record_id) = location.resolve();
        if !self.keystore.vault_exists(vault_id) {
            let key = self.keystore.create_key(vault_id);
            self.db.init_vault(key, vault_id);
        }
        let key = self.keystore.take_key(vault_id).unwrap();
        let res = self.db.write(&key, vault_id, record_id, &value, hint);
        self.keystore.entry_or_insert_key(vault_id, key);
        res
    }

    fn revoke_data(&mut self, location: &Location) -> Result<(), RecordError> {
        let (vault_id, record_id) = location.resolve();
        if let Some(key) = self.keystore.take_key(vault_id) {
            let res = self.db.revoke_record(&key, vault_id, record_id);
            self.keystore.entry_or_insert_key(vault_id, key);
            res?;
        }
        Ok(())
    }

    fn garbage_collect(&mut self, vault_id: VaultId) -> bool {
        let key = match self.keystore.take_key(vault_id) {
            Some(key) => key,
            None => return false,
        };
        self.db.garbage_collect_vault(&key, vault_id);
        self.keystore.entry_or_insert_key(vault_id, key);
        true
    }
}
