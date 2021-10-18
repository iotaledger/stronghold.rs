// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::vault::{
    crypto_box::{BoxProvider, Decrypt, Encrypt, Key},
    types::{
        transactions::{DataTransaction, RevocationTransaction, SealedBlob, SealedTransaction},
        utils::{BlobId, ChainId, RecordHint, RecordId, VaultId},
    },
};

use runtime::GuardedVec;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt::Debug};
use thiserror::Error as DeriveError;

use super::crypto_box::DecryptError;

#[derive(DeriveError)]
pub enum ProcedureError<P: BoxProvider, E: Debug> {
    #[error("Vault `{0:?}` does not exist.")]
    MissingVault(VaultId),

    #[error("Record Error: `{0:?}`")]
    Record(#[from] RecordError<P>),

    #[error("Procedure Error `{0:?}`")]
    Procedure(E),
}

impl<P: BoxProvider, E: Debug> Debug for ProcedureError<P, E> {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProcedureError::MissingVault(e) => fmt.debug_tuple("ProcedureError::MissingVault").field(&e).finish(),
            ProcedureError::Record(e) => fmt.debug_tuple("ProcedureError::Record").field(&e).finish(),
            ProcedureError::Procedure(e) => fmt.debug_tuple("ProcedureError::Procedure").field(&e).finish(),
        }
    }
}

#[derive(DeriveError)]
pub enum RecordError<P: BoxProvider> {
    #[error("Decryption Failed: `{0:?}`")]
    Decryption(#[from] DecryptError<P::OpenError>),

    #[error("Found Invalid Transaction")]
    InvalidTransaction,

    #[error("Encryption Failed: `{0:?}`")]
    Encryption(P::SealError),

    #[error("Invalid Key provided")]
    InvalidKey,

    #[error("Not record with `{0:?}`")]
    MissingRecord(ChainId),

    #[error("Failed to generate random Id: `{0:?}`")]
    IdError(P::RandomnessError),
}

impl<P: BoxProvider> Debug for RecordError<P> {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordError::Decryption(e) => fmt.debug_tuple("RecordError::Decryption").field(&e).finish(),
            RecordError::InvalidTransaction => fmt.write_str("RecordError::InvalidTransaction"),
            RecordError::Encryption(e) => fmt.debug_tuple("RecordError::Encryption").field(&e).finish(),
            RecordError::InvalidKey => fmt.write_str("RecordError::InvalidKey"),
            RecordError::MissingRecord(id) => fmt.debug_tuple("RecordError::MissingRecord").field(&id).finish(),
            RecordError::IdError(e) => fmt.debug_tuple("RecordError::IdError").field(&e).finish(),
        }
    }
}

/// A view over the data inside of a collection of [`Vault`] types.
#[derive(Deserialize, Serialize, Clone, Default)]
pub struct DbView<P: BoxProvider> {
    /// A hashmap of the [`Vault`] types.
    pub vaults: HashMap<VaultId, Vault<P>>,
}

/// A enclave of data that is encrypted under one [`Key`].
#[derive(Deserialize, Serialize, Clone)]
pub struct Vault<P: BoxProvider> {
    key: Key<P>,
    entries: HashMap<ChainId, Record>,
}

/// A bit of data inside of a [`Vault`].
#[derive(Deserialize, Serialize, Clone)]
pub struct Record {
    /// record id.
    id: ChainId,
    /// data transaction metadata.
    data: SealedTransaction,
    /// revocation transaction metadata.
    revoke: Option<SealedTransaction>,
    /// encrypted data in blob format.
    blob: SealedBlob,
}

impl<P: BoxProvider> DbView<P> {
    /// Create a new [`DbView`] to interface with the [`Vault`] types in the database.
    pub fn new() -> DbView<P> {
        let vaults = HashMap::new();

        Self { vaults }
    }

    /// Initialize a new [`Vault`] if it doesn't exist.
    pub fn init_vault(&mut self, key: &Key<P>, vid: VaultId) {
        self.vaults.entry(vid).or_insert_with(|| Vault::init_vault(key));
    }

    /// Write a new record to a [`Vault`]. Will instead update a [`Record`] if it already exists.
    pub fn write(
        &mut self,
        key: &Key<P>,
        vid: VaultId,
        rid: RecordId,
        data: &[u8],
        record_hint: RecordHint,
    ) -> Result<(), RecordError<P>> {
        if !self.vaults.contains_key(&vid) {
            self.init_vault(key, vid);
        }

        let vault = self.vaults.get_mut(&vid).expect("Vault was inited.");
        vault.add_or_update_record(key, rid.0, data, record_hint)
    }

    /// Lists all of the [`RecordHint`] values and [`RecordId`] values for the given [`Vault`].
    pub fn list_hints_and_ids(&self, key: &Key<P>, vid: VaultId) -> Vec<(RecordId, RecordHint)> {
        let buf: Vec<(RecordId, RecordHint)> = if let Some(vault) = self.vaults.get(&vid) {
            vault.list_hints_and_ids(key)
        } else {
            vec![]
        };

        buf
    }

    /// Check to see if a [`Vault`] contains a [`Record`] through the given [`RecordId`].
    pub fn contains_record(&mut self, key: &Key<P>, vid: VaultId, rid: RecordId) -> bool {
        if let Some(vault) = self.vaults.get(&vid) {
            vault.contains_record(key, rid)
        } else {
            false
        }
    }

    /// Get access the decrypted [`GuardedVec`] of the specified [`Record`].
    pub fn get_guard<E, F>(
        &mut self,
        key: &Key<P>,
        vid: VaultId,
        rid: RecordId,
        f: F,
    ) -> Result<(), ProcedureError<P, E>>
    where
        F: FnOnce(GuardedVec<u8>) -> Result<(), E>,
        E: Debug,
    {
        let vault = self.vaults.get_mut(&vid).ok_or(ProcedureError::MissingVault(vid))?;
        let guard = vault.get_guard(key, rid.0).map_err(ProcedureError::Record)?;
        f(guard).map_err(ProcedureError::Procedure)
    }

    /// Access the decrypted [`GuardedVec`] of the specified [`Record`] and place the return value into the second
    /// specified [`Record`]
    #[allow(clippy::too_many_arguments)]
    pub fn exec_proc<E, F>(
        &mut self,
        key0: &Key<P>,
        vid0: VaultId,
        rid0: RecordId,
        key1: &Key<P>,
        vid1: VaultId,
        rid1: RecordId,
        hint: RecordHint,
        f: F,
    ) -> Result<(), ProcedureError<P, E>>
    where
        F: FnOnce(GuardedVec<u8>) -> Result<Vec<u8>, E>,
        E: Debug,
    {
        let vault = self.vaults.get_mut(&vid0).ok_or(ProcedureError::MissingVault(vid0))?;

        let guard = vault.get_guard(key0, rid0.0).map_err(ProcedureError::Record)?;

        let data = f(guard).map_err(ProcedureError::Procedure)?;

        self.write(key1, vid1, rid1, &data, hint)
            .map_err(ProcedureError::Record)
    }

    /// Add a revocation transaction to the [`Record`]
    pub fn revoke_record(&mut self, key: &Key<P>, vid: VaultId, rid: RecordId) -> Result<(), RecordError<P>> {
        if let Some(vault) = self.vaults.get_mut(&vid) {
            vault.revoke(key, rid.0)?;
        }
        Ok(())
    }

    /// Garbage collect a [`Vault`]. Deletes any records that contain revocation transactions.
    pub fn garbage_collect_vault(&mut self, key: &Key<P>, vid: VaultId) {
        if let Some(vault) = self.vaults.get_mut(&vid) {
            if &vault.key == key {
                vault.garbage_collect();
            }
        }
    }

    /// Clears the entire [`Vault`] from memory.
    pub fn clear(&mut self) {
        self.vaults.clear();
    }
}

impl<P: BoxProvider> Vault<P> {
    /// Initialize a new [`Vault`]
    pub fn init_vault(key: &Key<P>) -> Vault<P> {
        let entries = HashMap::new();

        Self {
            entries,
            key: key.clone(),
        }
    }

    /// Adds a new [`Record`] to the [`Vault`] if the [`Record`] doesn't already exist. Otherwise, updates the data in
    /// the existing [`Record`] as long as it hasn't been revoked.
    pub fn add_or_update_record(
        &mut self,
        key: &Key<P>,
        id: ChainId,
        data: &[u8],
        record_hint: RecordHint,
    ) -> Result<(), RecordError<P>> {
        if key != &self.key {
            return Err(RecordError::InvalidKey);
        }

        let blob_id = BlobId::random::<P>().map_err(RecordError::IdError)?;
        if let Some(entry) = self.entries.get_mut(&id) {
            entry.update(key, id, data)?
        } else {
            let entry = Record::new(key, id, blob_id, data, record_hint).map_err(RecordError::Encryption)?;
            self.entries.insert(id, entry);
        }

        Ok(())
    }

    /// List the [`RecordHint`] values and [`RecordId`] values of the specified [`Vault`].
    pub(crate) fn list_hints_and_ids(&self, key: &Key<P>) -> Vec<(RecordId, RecordHint)> {
        let mut buf: Vec<(RecordId, RecordHint)> = Vec::new();

        if key == &self.key {
            buf = self
                .entries
                .values()
                .into_iter()
                .filter_map(|entry| entry.get_hint_and_id(key))
                .collect();
        }

        buf
    }

    /// Check if the [`Vault`] contains a [`Record`]
    fn contains_record(&self, key: &Key<P>, rid: RecordId) -> bool {
        if key == &self.key {
            self.entries.values().into_iter().any(|entry| entry.check_id(rid))
        } else {
            false
        }
    }

    /// Revokes an [`Record`] by its [`ChainId`].  Does nothing if the [`Record`] doesn't exist.
    pub fn revoke(&mut self, key: &Key<P>, id: ChainId) -> Result<(), RecordError<P>> {
        if key != &self.key {
            return Err(RecordError::InvalidKey);
        }
        if let Some(entry) = self.entries.get_mut(&id) {
            entry.revoke(key, id)?;
        }
        Ok(())
    }

    /// Gets the decrypted [`GuardedVec`] from the [`Record`]
    pub fn get_guard(&self, key: &Key<P>, id: ChainId) -> Result<GuardedVec<u8>, RecordError<P>> {
        if key != &self.key {
            return Err(RecordError::InvalidKey);
        }
        let entry = self.entries.get(&id).ok_or(RecordError::MissingRecord(id))?;
        entry.get_blob(key, id)
    }

    /// Sorts through all of the vault entries and garbage collects any revoked entries.
    pub fn garbage_collect(&mut self) {
        // get the keys of the entries with the revocation transactions.
        let garbage: Vec<ChainId> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.revoke.is_some())
            .map(|(c, _)| *c)
            .collect();

        // remove the garbage entries from the database.
        garbage.iter().for_each(|c| {
            self.entries.remove(c);
        });
    }
}

impl Record {
    // create a new [`Record`].
    pub fn new<P: BoxProvider>(
        key: &Key<P>,
        id: ChainId,
        blob: BlobId,
        data: &[u8],
        hint: RecordHint,
    ) -> Result<Record, P::SealError> {
        let len = data.len() as u64;
        let dtx = DataTransaction::new(id, len, blob, hint);

        let blob: SealedBlob = data.encrypt(key, blob)?;
        let data = dtx.encrypt(key, id)?;

        Ok(Record {
            id,
            data,
            blob,
            revoke: None,
        })
    }

    /// gets the [`RecordHint`] and [`RecordId`] of the [`Record`].
    fn get_hint_and_id<P: BoxProvider>(&self, key: &Key<P>) -> Option<(RecordId, RecordHint)> {
        if self.revoke.is_none() {
            let tx = self.data.decrypt(key, self.id).expect("Unable to decrypt transaction");

            let tx = tx
                .typed::<DataTransaction>()
                .expect("Failed to convert to data transaction");

            let hint = tx.record_hint;
            let id = RecordId(self.id);

            Some((id, hint))
        } else {
            None
        }
    }

    /// Check to see if a [`RecordId`] pairs with the [`Record`]. Comes back as false if there is a revocation
    /// transaction
    fn check_id(&self, rid: RecordId) -> bool {
        if self.revoke.is_none() {
            rid.0 == self.id
        } else {
            false
        }
    }

    /// Get the blob from this [`Record`].
    fn get_blob<P: BoxProvider>(&self, key: &Key<P>, id: ChainId) -> Result<GuardedVec<u8>, RecordError<P>> {
        // check if id id and tx id match.
        if self.id == id {
            // check if there is a revocation transaction.
            if self.revoke.is_none() {
                let tx = self.data.decrypt(key, self.id)?;
                let tx = tx.typed::<DataTransaction>().ok_or(RecordError::InvalidTransaction)?;

                let guarded = GuardedVec::new(tx.len.u64() as usize, |i| {
                    let blob = SealedBlob::from(self.blob.as_ref())
                        .decrypt(key, tx.blob)
                        .expect("Unable to decrypt blob");

                    i.copy_from_slice(blob.as_ref());
                });

                Ok(guarded)
            } else {
                Ok(GuardedVec::zero(0))
            }
        } else {
            Err(RecordError::MissingRecord(id))
        }
    }

    /// Update the data in an existing [`Record`].
    fn update<P: BoxProvider>(&mut self, key: &Key<P>, id: ChainId, new_data: &[u8]) -> Result<(), RecordError<P>> {
        // check if ids match
        if self.id == id {
            // check if a revocation transaction exists.
            if self.revoke.is_none() {
                // decrypt data transaction.
                let tx = self.data.decrypt(key, self.id).map_err(RecordError::Decryption)?;
                let tx = tx.typed::<DataTransaction>().ok_or(RecordError::InvalidTransaction)?;

                // create a new sealed blob with the new_data.
                let blob: SealedBlob = new_data.encrypt(key, tx.blob).map_err(RecordError::Encryption)?;
                // create a new sealed transaction with the new_data length.
                let dtx = DataTransaction::new(tx.id, new_data.len() as u64, tx.blob, tx.record_hint);
                let data = dtx.encrypt(key, tx.id).map_err(RecordError::Encryption)?;

                self.blob = blob;
                self.data = data;
            }
        }

        Ok(())
    }

    // add a revocation transaction to the [`Record`].
    fn revoke<P: BoxProvider>(&mut self, key: &Key<P>, id: ChainId) -> Result<(), RecordError<P>> {
        // check if id and id match.
        if self.id != id {
            return Err(RecordError::MissingRecord(id));
        }

        // check if revoke transaction already exists.
        if self.revoke.is_none() {
            let revoke = RevocationTransaction::new(self.id)
                .encrypt(key, self.id)
                .map_err(RecordError::Encryption)?;
            self.revoke = Some(revoke);
        }

        Ok(())
    }
}
