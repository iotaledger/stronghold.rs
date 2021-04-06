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
#[derive(Deserialize, Serialize)]
pub struct DbView<P: BoxProvider> {
    pub vaults: HashMap<VaultId, Vault<P>>,
}

/// A enclave of data that is encrypted under one key.
#[derive(Deserialize, Serialize)]
pub struct Vault<P: BoxProvider> {
    key: Key<P>,
    entries: HashMap<ChainId, Entry>,
}

/// A bit of data inside of a Vault.
#[derive(Deserialize, Serialize)]
pub struct Entry {
    id: ChainId,
    data: SealedTransaction,
    revoke: Option<SealedTransaction>,
    blob: SealedBlob,
}

impl<P: BoxProvider> DbView<P> {
    pub fn new() -> DbView<P> {
        let vaults = HashMap::new();

        Self { vaults }
    }

    pub fn init_vault(&mut self, key: &Key<P>, vid: VaultId) -> crate::Result<()> {
        self.vaults.entry(vid).or_insert(Vault::init_vault(key)?);

        Ok(())
    }

    pub fn write(
        &mut self,
        key: &Key<P>,
        vid: VaultId,
        rid: RecordId,
        data: &[u8],
        record_hint: RecordHint,
    ) -> crate::Result<()> {
        self.vaults.entry(vid).and_modify(|vault| {
            vault
                .add_or_update_entry(key, rid.0, data, record_hint)
                .expect("unable to write record")
        });

        Ok(())
    }

    pub fn execute_proc<F>(&mut self, key: &Key<P>, vid: VaultId, rid: RecordId, f: F) -> crate::Result<()>
    where
        F: FnOnce(GuardedVec<u8>) -> crate::Result<()>,
    {
        if let Some(vault) = self.vaults.get_mut(&vid) {
            let guard = vault.get_guard(key, rid.0)?;

            f(guard)?;
        }

        Ok(())
    }

    pub fn revoke_record(&mut self, key: &Key<P>, vid: VaultId, rid: RecordId) -> crate::Result<()> {
        if let Some(vault) = self.vaults.get_mut(&vid) {
            vault.revoke(key, rid.0)?;
        }

        Ok(())
    }

    pub fn garbage_collect_vault(&mut self, key: &Key<P>, vid: VaultId) -> crate::Result<()> {
        if let Some(vault) = self.vaults.get_mut(&vid) {
            if &vault.key == key {
                vault.garbage_collect();
            }
        }

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
    pub fn add_or_update_entry(
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
                .or_insert(Entry::new(key, id, blob_id, data, record_hint)?);
        }
        Ok(())
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

    pub fn get_guard(&mut self, key: &Key<P>, id: ChainId) -> crate::Result<GuardedVec<u8>> {
        if key == &self.key {
            if let Some(entry) = self.entries.get(&id) {
                entry.get_blob(key, id)
            } else {
                Err(crate::Error::DatabaseError("Invalid record id.".into()))
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

impl Entry {
    // create a new entry in the vault.
    pub fn new<P: BoxProvider>(
        key: &Key<P>,
        id: ChainId,
        blob: BlobId,
        data: &[u8],
        hint: RecordHint,
    ) -> crate::Result<Entry> {
        let len = data.len() as u64;
        let dtx = DataTransaction::new(id, len, blob, hint);

        let blob: SealedBlob = data.encrypt(key, blob)?;
        let data = dtx.encrypt(key, id)?;

        Ok(Entry {
            id,
            data,
            blob,
            revoke: None,
        })
    }

    /// Get the blob from this entry.
    pub fn get_blob<P: BoxProvider>(&self, key: &Key<P>, id: ChainId) -> crate::Result<GuardedVec<u8>> {
        // check if id id and tx id match.
        if self.id == id {
            // check if there is a revocation transaction.
            if let None = self.revoke {
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
                Err(crate::Error::ValueError(
                    "Entry has been revoked and can't be read.".to_string(),
                ))
            }
        } else {
            Err(crate::Error::DatabaseError(
                "Invalid id for entry. Ids must match a valid entry.".to_string(),
            ))
        }
    }

    /// Update the data in an existing entry.
    pub fn update<P: BoxProvider>(&mut self, key: &Key<P>, id: ChainId, new_data: &[u8]) -> crate::Result<()> {
        // check if ids match
        if self.id == id {
            // check if a revocation transaction exists.
            if let None = self.revoke {
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
    pub fn revoke<P: BoxProvider>(&mut self, key: &Key<P>, id: ChainId) -> crate::Result<()> {
        // check if id and id match.
        if self.id == id {
            // check if revoke transaction already exists.
            if let None = self.revoke {
                let revoke = RevocationTransaction::new(self.id);

                self.revoke = Some(revoke.encrypt(key, self.id)?);
            }
        }

        Ok(())
    }
}
