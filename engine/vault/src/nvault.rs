// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    crypto_box::{BoxProvider, Decrypt, Encrypt, Key},
    types::{
        ntransactions::{DataTransaction, RevocationTransaction, SealedBlob, SealedTransaction},
        utils::{BlobId, ChainId, RecordHint, RecordId, VaultId},
    },
};

use serde::{Deserialize, Serialize};

use std::collections::HashMap;

use runtime::GuardedVec;

/// A view over the data inside of the Stronghold database.
#[derive(Deserialize, Serialize, Clone, Default)]
pub struct DbView<P: BoxProvider> {
    pub vaults: HashMap<VaultId, Vault<P>>,
}

/// A enclave of data that is encrypted under one key.
#[derive(Deserialize, Serialize, Clone)]
pub struct Vault<P: BoxProvider> {
    key: Key<P>,
    entries: HashMap<ChainId, Record>,
}

/// A bit of data inside of a Vault.
#[derive(Deserialize, Serialize, Clone)]
pub struct Record {
    id: ChainId,
    data: SealedTransaction,
    revoke: Option<SealedTransaction>,
    blob: SealedBlob,
}

impl<P: BoxProvider> DbView<P> {
    /// Create a new Database View.
    pub fn new() -> DbView<P> {
        let vaults = HashMap::new();

        Self { vaults }
    }

    /// Initialize a new vault if it doesn't exist.
    pub fn init_vault(&mut self, key: &Key<P>, vid: VaultId) -> crate::Result<()> {
        self.vaults.entry(vid).or_insert(Vault::init_vault(key)?);

        Ok(())
    }

    /// Write a new record to the Vault.
    pub fn write(
        &mut self,
        key: &Key<P>,
        vid: VaultId,
        rid: RecordId,
        data: &[u8],
        record_hint: RecordHint,
    ) -> crate::Result<()> {
        if !self.vaults.contains_key(&vid) {
            self.init_vault(&key, vid)?;
        }

        self.vaults.entry(vid).and_modify(|vault| {
            vault
                .add_or_update_record(key, rid.0, data, record_hint)
                .expect("unable to write record")
        });

        Ok(())
    }

    /// Lists all of the hints and ids for the given vault.
    pub fn list_hints_and_ids(&self, key: &Key<P>, vid: VaultId) -> Vec<(RecordId, RecordHint)> {
        let buf: Vec<(RecordId, RecordHint)> = if let Some(vault) = self.vaults.get(&vid) {
            vault.list_hints_and_ids(&key)
        } else {
            vec![]
        };

        buf
    }

    /// Check to see if vault contains a specific record id.
    pub fn contains_record(&mut self, key: &Key<P>, vid: VaultId, rid: RecordId) -> bool {
        if let Some(vault) = self.vaults.get(&vid) {
            vault.contains_record(key, rid)
        } else {
            false
        }
    }

    /// execute a procedure on the guarded record data.
    pub fn get_guard<F>(&mut self, key: &Key<P>, vid: VaultId, rid: RecordId, f: F) -> crate::Result<()>
    where
        F: FnOnce(GuardedVec<u8>) -> crate::Result<()>,
    {
        if let Some(vault) = self.vaults.get_mut(&vid) {
            let guard = vault.get_guard(key, rid.0)?;

            f(guard)?;
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn exec_proc<F>(
        &mut self,
        key0: &Key<P>,
        vid0: VaultId,
        rid0: RecordId,
        key1: &Key<P>,
        vid1: VaultId,
        rid1: RecordId,
        hint: RecordHint,
        f: F,
    ) -> crate::Result<()>
    where
        F: FnOnce(GuardedVec<u8>) -> crate::Result<Vec<u8>>,
    {
        if let Some(vault) = self.vaults.get_mut(&vid0) {
            let guard = vault.get_guard(key0, rid0.0)?;

            let data = f(guard)?;

            if self.vaults.get(&vid1).is_none() {
                self.init_vault(&key1, vid1)?;
            }

            self.write(&key1, vid1, rid1, &data, hint)?;
        }

        Ok(())
    }

    /// mark a record as revoked.
    pub fn revoke_record(&mut self, key: &Key<P>, vid: VaultId, rid: RecordId) -> crate::Result<()> {
        if let Some(vault) = self.vaults.get_mut(&vid) {
            vault.revoke(key, rid.0)?;
        }

        Ok(())
    }

    /// Garbage collect a vault.
    pub fn garbage_collect_vault(&mut self, key: &Key<P>, vid: VaultId) -> crate::Result<()> {
        if let Some(vault) = self.vaults.get_mut(&vid) {
            if &vault.key == key {
                vault.garbage_collect();
            }
        }

        Ok(())
    }

    pub fn clear(&mut self) -> crate::Result<()> {
        self.vaults.clear();

        Ok(())
    }
}

impl<P: BoxProvider> Vault<P> {
    pub fn init_vault(key: &Key<P>) -> crate::Result<Vault<P>> {
        let entries = HashMap::new();

        Ok(Self {
            entries,
            key: key.clone(),
        })
    }

    /// Adds a new entry to the vault if the entry doesn't already exist. Otherwise, updates the data in the existing
    /// entry as long as it hasn't been revoked.
    pub fn add_or_update_record(
        &mut self,
        key: &Key<P>,
        id: ChainId,
        data: &[u8],
        record_hint: RecordHint,
    ) -> crate::Result<()> {
        let blob_id = BlobId::random::<P>()?;

        if key == &self.key {
            self.entries
                .entry(id)
                .and_modify(|entry| {
                    entry.update(key, id, data).expect("Unable to update entry");
                })
                .or_insert(Record::new(key, id, blob_id, data, record_hint)?);
        }
        Ok(())
    }

    /// List the hints and ids of the specified vault.
    pub(crate) fn list_hints_and_ids(&self, key: &Key<P>) -> Vec<(RecordId, RecordHint)> {
        let mut buf: Vec<(RecordId, RecordHint)> = Vec::new();

        if key == &self.key {
            buf = self
                .entries
                .values()
                .into_iter()
                .filter_map(|entry| entry.get_hint_and_id(&key))
                .collect();
        }

        buf
    }

    fn contains_record(&self, key: &Key<P>, rid: RecordId) -> bool {
        if key == &self.key {
            self.entries.values().into_iter().any(|entry| entry.check_id(rid))
        } else {
            false
        }
    }

    /// Revokes an entry by its chain id.  Does nothing if the entry doesn't exist.
    pub fn revoke(&mut self, key: &Key<P>, id: ChainId) -> crate::Result<()> {
        if key == &self.key {
            if let Some(entry) = self.entries.get_mut(&id) {
                entry.revoke(key, id)?;
            }
        }

        Ok(())
    }

    pub fn get_guard(&self, key: &Key<P>, id: ChainId) -> crate::Result<GuardedVec<u8>> {
        if key == &self.key {
            if let Some(entry) = self.entries.get(&id) {
                entry.get_blob(key, id)
            } else {
                Ok(GuardedVec::random(0))
            }
        } else {
            Err(crate::Error::DatabaseError("Invalid key.".into()))
        }
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
    // create a new entry in the vault.
    pub fn new<P: BoxProvider>(
        key: &Key<P>,
        id: ChainId,
        blob: BlobId,
        data: &[u8],
        hint: RecordHint,
    ) -> crate::Result<Record> {
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

    /// Get the id and record hint for this record.
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

    /// Check to see if a record id is in this vault.
    fn check_id(&self, rid: RecordId) -> bool {
        if self.revoke.is_none() {
            rid.0 == self.id
        } else {
            false
        }
    }

    /// Get the blob from this entry.
    fn get_blob<P: BoxProvider>(&self, key: &Key<P>, id: ChainId) -> crate::Result<GuardedVec<u8>> {
        // check if id id and tx id match.
        if self.id == id {
            // check if there is a revocation transaction.
            if self.revoke.is_none() {
                let tx = self.data.decrypt(key, self.id).expect("Unable to decrypt tx");
                let tx = tx
                    .typed::<DataTransaction>()
                    .expect("Failed to cast as data transaction");

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
            Err(crate::Error::DatabaseError(
                "Invalid id for entry. Ids must match a valid entry.".to_string(),
            ))
        }
    }

    /// Update the data in an existing entry.
    fn update<P: BoxProvider>(&mut self, key: &Key<P>, id: ChainId, new_data: &[u8]) -> crate::Result<()> {
        // check if ids match
        if self.id == id {
            // check if a revocation transaction exists.
            if self.revoke.is_none() {
                // decrypt data transaction.
                let tx = self.data.decrypt(key, self.id)?;
                let tx = tx
                    .typed::<DataTransaction>()
                    .expect("Unable to cast to data transaction");

                // create a new sealed blob with the new_data.
                let blob: SealedBlob = new_data.encrypt(key, tx.blob)?;
                // create a new sealed transaction with the new_data length.
                let dtx = DataTransaction::new(tx.id, new_data.len() as u64, tx.blob, tx.record_hint);
                let data = dtx.encrypt(key, tx.id)?;

                self.blob = blob;
                self.data = data;
            }
        }

        Ok(())
    }

    // add a recovation transaction to an entry.
    fn revoke<P: BoxProvider>(&mut self, key: &Key<P>, id: ChainId) -> crate::Result<()> {
        // check if id and id match.
        if self.id == id {
            // check if revoke transaction already exists.
            if self.revoke.is_none() {
                let revoke = RevocationTransaction::new(self.id);

                self.revoke = Some(revoke.encrypt(key, self.id)?);
            }
        }

        Ok(())
    }
}
