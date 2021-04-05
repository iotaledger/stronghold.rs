// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    crypto_box::{BoxProvider, Decrypt, Encrypt, Key},
    types::{
        ntransactions::{DataTransaction, RevocationTransaction, SealedBlob, SealedTransaction},
        utils::{BlobId, ChainId, RecordHint, VaultId},
    },
};

use serde::{Deserialize, Serialize};

use std::collections::HashMap;

use runtime::GuardedVec;

/// A view over the data inside of the Stronghold database.
pub struct DbView<P: BoxProvider> {
    vaults: HashMap<VaultId, Vault<P>>,
}

/// A enclave of data that is encrypted under one key.
pub struct Vault<P: BoxProvider> {
    key: Key<P>,
    entries: HashMap<ChainId, Entry>,
}

/// A bit of data inside of a Vault.
pub struct Entry {
    id: ChainId,

    data: SealedTransaction,
    revoke: Option<SealedTransaction>,
    blob: SealedBlob,
}

impl<P: BoxProvider> Vault<P> {
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
        key: Key<P>,
        id: ChainId,
        blob: BlobId,
        data: &[u8],
        hint: RecordHint,
    ) -> crate::Result<Entry> {
        let len = data.len() as u64;
        let dtx = DataTransaction::new(id, len, blob, hint);

        let blob: SealedBlob = data.encrypt(&key, blob)?;
        let data = dtx.encrypt(&key, id)?;

        Ok(Entry {
            id,
            data,
            blob,
            revoke: None,
        })
    }

    /// Get the blob from this entry.
    pub fn get_blob<P: BoxProvider>(&self, key: Key<P>, id: ChainId) -> crate::Result<GuardedVec<u8>> {
        // check if id id and tx id match.
        if self.id == id {
            // check if there is a revocation transaction.
            if let None = self.revoke {
                let tx = self.data.decrypt(&key, self.id).expect("Unable to decrypt tx");
                let tx = tx
                    .typed::<DataTransaction>()
                    .expect("Failed to cast as data transaction");

                let guarded = GuardedVec::new(tx.len.u64() as usize, |i| {
                    let blob = SealedBlob::from(self.data.as_ref())
                        .decrypt(&key, tx.blob)
                        .expect("Unable to decrypt the data");

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
                "Invalid ids for entry. Id's must match a valid entry.".to_string(),
            ))
        }
    }

    /// Update the data in an existing entry.
    pub fn update<P: BoxProvider>(&mut self, key: Key<P>, id: ChainId, new_data: &[u8]) -> crate::Result<()> {
        // check if ids match
        if self.id == id {
            // check if a revocation transaction exists.
            if let None = self.revoke {
                // decrypt data transaction.
                let tx = self.data.decrypt(&key, self.id)?;
                let tx = tx
                    .typed::<DataTransaction>()
                    .expect("Unable to cast to data transaction");

                // create a new sealed blob with the new_data.
                let blob: SealedBlob = new_data.encrypt(&key, tx.blob)?;
                // create a new sealed transaction with the new_data length.
                let dtx = DataTransaction::new(tx.id, new_data.len() as u64, tx.blob, tx.record_hint);
                let data = dtx.encrypt(&key, tx.id)?;

                self.blob = blob;
                self.data = data;
            }
        }

        Ok(())
    }

    // add a recovation transaction to an entry.
    pub fn revoke<P: BoxProvider>(&mut self, key: Key<P>, id: ChainId) -> crate::Result<()> {
        // check if id and id match.
        if self.id == id {
            // check if revoke transaction already exists.
            if let None = self.revoke {
                let revoke = RevocationTransaction::new(self.id);

                self.revoke = Some(revoke.encrypt(&key, self.id)?);
            }
        }

        Ok(())
    }
}
