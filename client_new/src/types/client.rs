// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
use std::{
    error::Error,
    sync::{Arc, RwLock},
};

use engine::{
    new_runtime::memories::buffer::Buffer,
    vault::{ClientId, DbView, RecordError, RecordHint, VaultError, VaultId},
};

use crate::{KeyStore, Location, Provider, Store, Vault};

pub struct Client {
    // store: Option<Arc<Store>>,
    vault: Option<Arc<Vault>>,
    // A keystore
    pub(crate) keystore: KeyStore<Provider>,

    // A view on the vault entries
    pub(crate) db: Arc<RwLock<DbView<Provider>>>,

    // The id of this client
    pub id: ClientId,

    // Contains the Record Ids for the most recent Record in each vault.
    pub store: Arc<Store>,
}

impl Default for Client {
    fn default() -> Self {
        todo!()
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        // ..
    }
}

impl Client {
    /// Returns an atomic reference to the [`Store`]
    pub async fn store(&self) -> Arc<Store> {
        self.store.clone()
    }

    /// Returns a [`Vault`] according to path
    pub async fn vault<P>(&self, path: P) -> Vault
    where
        P: AsRef<Vec<u8>>,
    {
        todo!()
    }

    /// Returns ok, if a vault exists
    pub async fn check_vault(&self) -> Result<(), Box<dyn Error>> {
        todo!()
    }

    /// Returns Ok, if the record exists
    pub async fn check_record(&self) -> Result<(), Box<dyn Error>> {
        todo!()
    }

    /// Returns the [`ClientId`] of the client
    pub async fn id(&self) -> &ClientId {
        &self.id
    }

    pub async fn update<S>(&self, snapshot: S) -> Result<(), Box<dyn Error>> {
        todo!()
    }
}
