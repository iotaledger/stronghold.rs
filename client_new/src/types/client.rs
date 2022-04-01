// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
use super::snapshot;
use crate::{
    derive_vault_id,
    procedures::{
        FatalProcedureError, Procedure, ProcedureError, ProcedureOutput, Products, Runner, StrongholdProcedure,
    },
    ClientError, ClientState, ClientVault, KeyStore, Location, Provider, RecordError, Store,
};
use engine::{
    new_runtime::memories::buffer::Buffer,
    vault::{view::Record, BoxProvider, ClientId, DbView, RecordHint, VaultId},
};
use std::{
    error::Error,
    sync::{Arc, RwLock},
};

#[cfg(feature = "p2p")]
use stronghold_p2p::{identity::Keypair, AuthenticKeypair, NoiseKeypair, PeerId};

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
    pub fn store(&self) -> Store {
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
    pub fn vault_exists<P>(&self, vault_path: P) -> Result<bool, ClientError>
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
    pub fn record_exists(&mut self, location: Location) -> Result<bool, ClientError> {
        let (vault_id, record_id) = location.resolve();
        let db = self.db.try_read().map_err(|_| ClientError::LockAcquireFailed)?;
        let contains_record = db.contains_record(vault_id, record_id);
        Ok(contains_record)
    }

    /// Returns the [`ClientId`] of the client
    ///
    /// # Example
    /// ```
    /// ```
    pub async fn id(&self) -> &ClientId {
        &self.id
    }

    /// Loads the state of [`Self`] from a [`ClientState`]. Replaces all previous data.
    ///
    /// # Example
    /// ```
    /// ```
    pub fn load(&self, state: ClientState, id: ClientId) -> Result<(), ClientError> {
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
    pub fn execute_procedure<P>(&self, procedure: P) -> Result<P::Output, ProcedureError>
    where
        P: Procedure + Into<StrongholdProcedure>,
    {
        let res = self.execure_procedure_chained(vec![procedure.into()]);
        let mapped = res.map(|mut vec| vec.pop().unwrap().try_into().ok().unwrap())?;
        Ok(mapped)
    }

    /// Executes a list of cryptographic [`Procedures`] sequentially and returns a collected output
    ///
    /// # Example
    /// ```no_run
    /// ```
    pub fn execure_procedure_chained(
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

#[cfg(feature = "p2p")]
impl Client {
    /// This generates a new [`Keypair`] and stores it in a [`Location`]. The new
    /// keypair will be used for Stronghold's networking capability
    ///
    /// # Example
    /// ```
    /// ```
    pub(crate) fn generate_p2p_keypair(&self, location: Location) -> Result<(), ClientError> {
        self.write_p2p_keypair(Keypair::generate_ed25519(), location)
    }

    /// Writes an existing [`Keypair`] into [`Location`]
    ///
    /// # Example
    /// ```
    /// ```
    pub(crate) fn write_p2p_keypair(&self, keypair: Keypair, location: Location) -> Result<(), ClientError> {
        let bytes = keypair
            .to_protobuf_encoding()
            .map_err(|e| ClientError::Inner(e.to_string()))?;

        let vault = self.vault(location.clone());
        vault.write_secret(location, bytes)?;

        Ok(())
    }

    /// Derive a new noise keypair from a stored p2p-keypair.
    /// Returns the new keypair and the `PeerId` that is derived from the public
    /// key of the stored keypair.
    ///
    /// ## Note
    /// The keypair differs for each new derivation, the `PeerId` is consistent.
    ///
    /// # Example
    /// ```
    /// ```
    pub(crate) fn derive_noise_keypair(&self, location: Location) -> Result<(PeerId, AuthenticKeypair), ClientError> {
        let mut id_keys = None;
        let f = |guard: Buffer<u8>| {
            let keys = Keypair::from_protobuf_encoding(&*guard.borrow()).map_err(|e| e.to_string())?;
            let _ = id_keys.insert(keys);
            Ok(())
        };
        self.get_guard(&location, f)
            .map_err(|e| ClientError::Inner(e.to_string()))?;
        let id_keys = id_keys.unwrap();
        let keypair = NoiseKeypair::new()
            .into_authentic(&id_keys)
            .map_err(|e| ClientError::Inner(e.to_string()))?;
        let peer_id = PeerId::from_public_key(&id_keys.public());
        Ok((peer_id, keypair))
    }
}
