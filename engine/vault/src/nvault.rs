// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    base64::Base64Encodable,
    crypto_box::{BoxProvider, Decrypt, Encrypt, Key},
    types::{
        ntransactions::{
            DataTransaction, InitTransaction, RevocationTransaction, SealedBlob, SealedTransaction, Transaction,
        },
        utils::{BlobId, ChainId, RecordHint, TransactionId, Val, VaultId},
    },
};

use serde::{Deserialize, Serialize};

use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    fmt::{self, Debug, Display, Formatter},
};

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
    chain: ChainId,
    id: TransactionId,
    len: usize,
    data: SealedTransaction,
    revoke: Option<SealedTransaction>,
    blob: SealedBlob,
}

impl Entry {
    pub fn new<P: BoxProvider>(
        key: Key<P>,
        chain: ChainId,
        id: TransactionId,
        blob: BlobId,
        data: &[u8],
        hint: RecordHint,
    ) -> Entry {
        let dtx = DataTransaction::new(chain, id, blob, hint);
        let len = data.len();
        let blob: SealedBlob = data.encrypt(&key, blob).expect("Unable to encrypt data");
        let data = dtx.encrypt(&key, id).expect("Unable to encrypt tx");

        Entry {
            chain,
            id,
            len,
            data,
            blob,
            revoke: None,
        }
    }

    pub fn get_blob<P: BoxProvider>(
        &self,
        key: Key<P>,
        chain: ChainId,
        id: TransactionId,
    ) -> crate::Result<GuardedVec<u8>> {
        if self.chain == chain && self.id == id {
            if let None = self.revoke {
                let guarded = GuardedVec::new(self.len, |i| {
                    let tx = self.data.decrypt(&key, self.id).expect("Unable to decrypt tx");
                    let tx = tx
                        .typed::<DataTransaction>()
                        .expect("Failed to cast as data transaction");

                    let blob = SealedBlob::from(self.data.as_ref())
                        .decrypt(&key, tx.blob)
                        .expect("Unable to decrypt the data");

                    i.copy_from_slice(blob.as_ref());
                });

                Ok(guarded)
            } else {
                Err(crate::Error::DatabaseError(
                    "Entry has been revoked and can't be read.".to_string(),
                ))
            }
        } else {
            Err(crate::Error::DatabaseError(
                "Invalid ids for entry. Id's must match a valid entry.".to_string(),
            ))
        }
    }

    pub fn revoke<P: BoxProvider>(&mut self, key: Key<P>) {
        if let None = self.revoke {
            let revoke = RevocationTransaction::new(self.chain, self.id);

            self.revoke = Some(revoke.encrypt(&key, self.id).expect("Unable to encrypt revocation tx"));
        }
    }
}
