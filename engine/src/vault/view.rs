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
use std::{collections::HashMap, convert::Infallible, fmt::Debug, ops::Deref};
use thiserror::Error as DeriveError;

use super::{crypto_box::DecryptError, types::transactions::Transaction};

#[derive(DeriveError, Debug)]
pub enum VaultError<TProvErr: Debug, TProcErr: Debug = Infallible> {
    #[error("vault `{0:?}` does not exist")]
    VaultNotFound(VaultId),

    #[error("record error: `{0:?}`")]
    Record(#[from] RecordError<TProvErr>),

    #[error("procedure error `{0:?}`")]
    Procedure(TProcErr),
}

#[derive(DeriveError, Debug)]
pub enum RecordError<TProvErr: Debug> {
    #[error("provider error: `{0:?}`")]
    Provider(TProvErr),

    #[error("decrypted content does not match expected format: {0}")]
    CorruptedContent(String),

    #[error("invalid key provided")]
    InvalidKey,

    #[error("no record with `{0:?}`")]
    RecordNotFound(ChainId),
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
    ) -> Result<(), RecordError<P::Error>> {
        if !self.vaults.contains_key(&vid) {
            self.init_vault(key, vid);
        }

        let vault = self.vaults.get_mut(&vid).expect("Vault was initiated");
        vault.add_or_update_record(key, rid.0, data, record_hint)
    }

    /// Lists all of the [`RecordHint`] values and [`RecordId`] values for the given [`Vault`].
    pub fn list_hints_and_ids(&self, key: &Key<P>, vid: VaultId) -> Vec<(RecordId, RecordHint)> {
        if let Some(vault) = self.vaults.get(&vid) {
            vault.list_hints_and_ids(key)
        } else {
            vec![]
        }
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
    ) -> Result<(), VaultError<P::Error, E>>
    where
        F: FnOnce(GuardedVec<u8>) -> Result<(), E>,
        E: Debug,
    {
        let vault = self.vaults.get_mut(&vid).ok_or(VaultError::VaultNotFound(vid))?;
        let guard = vault.get_guard(key, rid.0).map_err(VaultError::Record)?;
        f(guard).map_err(VaultError::Procedure)
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
    ) -> Result<(), VaultError<P::Error, E>>
    where
        F: FnOnce(GuardedVec<u8>) -> Result<Vec<u8>, E>,
        E: Debug,
    {
        let vault = self.vaults.get_mut(&vid0).ok_or(VaultError::VaultNotFound(vid0))?;

        let guard = vault.get_guard(key0, rid0.0).map_err(VaultError::Record)?;

        let data = f(guard).map_err(VaultError::Procedure)?;

        self.write(key1, vid1, rid1, &data, hint).map_err(VaultError::Record)
    }

    /// Add a revocation transaction to the [`Record`]
    pub fn revoke_record(&mut self, key: &Key<P>, vid: VaultId, rid: RecordId) -> Result<(), RecordError<P::Error>> {
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
    ) -> Result<(), RecordError<P::Error>> {
        if key != &self.key {
            return Err(RecordError::InvalidKey);
        }

        let blob_id = BlobId::random::<P>().map_err(RecordError::Provider)?;
        if let Some(entry) = self.entries.get_mut(&id) {
            entry.update_data(key, id, data)?
        } else {
            let entry = Record::new(key, id, blob_id, data, record_hint).map_err(RecordError::Provider)?;
            self.entries.insert(id, entry);
        }

        Ok(())
    }

    /// Extend entries with entries from another vault with the same key.
    /// In case of duplicated records, the existing record is dropped in favor of the new one.
    pub fn merge(&mut self, other: Self) -> Result<(), RecordError<P::Error>> {
        if other.key != self.key {
            return Err(RecordError::InvalidKey);
        }
        self.entries.extend(other.entries.into_iter());
        Ok(())
    }


    /// Update the key and re-encrypt all records with the new key.
    /// In case of an error during re-encryption the old state is restored.
    pub fn update_key(&mut self, old: &Key<P>, new: &Key<P>) -> Result<(), RecordError<P::Error>> {
        if old != &self.key {
            return Err(RecordError::InvalidKey);
        }
        let mut updated = HashMap::new();
        for (id, mut entry) in self.entries.clone() {
            entry.update_key(old, new, id)?;
            updated.insert(id, entry);
        }
        self.entries = updated;
        self.key = new.clone();
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
                .filter_map(|entry| entry.get_hint_and_id(key).ok())
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
    pub fn revoke(&mut self, key: &Key<P>, id: ChainId) -> Result<(), RecordError<P::Error>> {
        if key != &self.key {
            return Err(RecordError::InvalidKey);
        }
        if let Some(entry) = self.entries.get_mut(&id) {
            entry.revoke(key, id)?;
        }
        Ok(())
    }

    /// Gets the decrypted [`GuardedVec`] from the [`Record`]
    pub fn get_guard(&self, key: &Key<P>, id: ChainId) -> Result<GuardedVec<u8>, RecordError<P::Error>> {
        if key != &self.key {
            return Err(RecordError::InvalidKey);
        }
        let entry = self.entries.get(&id).ok_or(RecordError::RecordNotFound(id))?;
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
    ) -> Result<Record, P::Error> {
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

    fn get_transaction<P: BoxProvider>(&self, key: &Key<P>) -> Result<Transaction, RecordError<P::Error>> {
        // check if a revocation transaction exists.
        if self.revoke.is_none() {
            // decrypt data transaction.
            self.data.decrypt(key, self.id).map_err(|err| match err {
                DecryptError::Invalid => {
                    RecordError::CorruptedContent("Could not convert bytes into transaction structure".into())
                }
                DecryptError::Provider(e) => RecordError::Provider(e),
            })
        } else {
            Err(RecordError::RecordNotFound(self.id))
        }
    }

    /// gets the [`RecordHint`] and [`RecordId`] of the [`Record`].
    fn get_hint_and_id<P: BoxProvider>(&self, key: &Key<P>) -> Result<(RecordId, RecordHint), RecordError<P::Error>> {
        let tx = self.get_transaction(key)?;
        let tx = tx.typed::<DataTransaction>().ok_or_else(|| {
            RecordError::CorruptedContent("Could not type decrypted transaction as data-transaction".into())
        })?;
        let hint = tx.record_hint;
        let id = RecordId(self.id);
        Ok((id, hint))
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
    fn get_blob<P: BoxProvider>(&self, key: &Key<P>, id: ChainId) -> Result<GuardedVec<u8>, RecordError<P::Error>> {
        // check if ids match
        if self.id != id {
            return Err(RecordError::RecordNotFound(id));
        }

        let tx = self.get_transaction(key)?;
        let tx = tx.typed::<DataTransaction>().ok_or_else(|| {
            RecordError::CorruptedContent("Could not type decrypted transaction as data-transaction".into())
        })?;

        let guarded = GuardedVec::new(tx.len.u64() as usize, |i| {
            let blob = SealedBlob::from(self.blob.as_ref())
                .decrypt(key, tx.blob)
                .expect("Unable to decrypt blob");

            i.copy_from_slice(blob.as_ref());
        });

        Ok(guarded)
    }

    /// Update the data in an existing [`Record`].
    fn update_data<P: BoxProvider>(
        &mut self,
        key: &Key<P>,
        id: ChainId,
        new_data: &[u8],
    ) -> Result<(), RecordError<P::Error>> {
        // check if ids match
        if self.id != id {
            return Err(RecordError::RecordNotFound(id));
        }

        let tx = self.get_transaction(key)?;
        let tx = tx.typed::<DataTransaction>().ok_or_else(|| {
            RecordError::CorruptedContent("Could not type decrypted transaction as data-transaction".into())
        })?;

        // create a new sealed blob with the new_data.
        let blob: SealedBlob = new_data.encrypt(key, tx.blob).map_err(RecordError::Provider)?;
        // create a new sealed transaction with the new_data length.
        let dtx = DataTransaction::new(tx.id, new_data.len() as u64, tx.blob, tx.record_hint);
        let data = dtx.encrypt(key, tx.id).map_err(RecordError::Provider)?;

        self.blob = blob;
        self.data = data;

        Ok(())
    }

    /// Update the data in an existing [`Record`].
    fn update_key<P: BoxProvider>(
        &mut self,
        old: &Key<P>,
        new: &Key<P>,
        id: ChainId,
    ) -> Result<(), RecordError<P::Error>> {
        // check if ids match
        if self.id != id {
            return Err(RecordError::RecordNotFound(id));
        }

        let tx = self.get_transaction(old)?;
        let typed_tx = tx.typed::<DataTransaction>().ok_or_else(|| {
            RecordError::CorruptedContent("Could not type decrypted transaction as data-transaction".into())
        })?;

        // Re-encrypt the blob with the new key.
        let updated_blob = SealedBlob::from(self.blob.as_ref())
                .decrypt(old, typed_tx.blob)
                .map_err(|e| match e {
                    DecryptError::Provider(e) => RecordError::Provider(e),
                    DecryptError::Invalid => unreachable!("Vec<u8>: TryFrom<Vec<u8>> is infallible.")
                })?
                .encrypt(new, typed_tx.blob)
                .map_err(RecordError::Provider)?;

        // Re-encrypt meta data with new key.
        let updated_data = tx.encrypt(new, typed_tx.id).map_err(RecordError::Provider)?;

        self.blob = updated_blob;
        self.data = updated_data;

        Ok(())
    }

    // add a revocation transaction to the [`Record`].
    fn revoke<P: BoxProvider>(&mut self, key: &Key<P>, id: ChainId) -> Result<(), RecordError<P::Error>> {
        // check if id and id match.
        if self.id != id {
            return Err(RecordError::RecordNotFound(id));
        }

        // check if revoke transaction already exists.
        if self.revoke.is_none() {
            let revoke = RevocationTransaction::new(self.id)
                .encrypt(key, self.id)
                .map_err(RecordError::Provider)?;
            self.revoke = Some(revoke);
        }

        Ok(())
    }
}
