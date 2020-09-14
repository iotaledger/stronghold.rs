// Copyright 2020 IOTA Stiftung
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use crate::{
    crypto_box::{BoxProvider, Key, Encrypt, Decrypt},
    types::{
        transactions::{Transaction, DataTransaction, InitTransaction, RevocationTransaction, SealedTransaction},
        utils::{TransactionId, ChainId, RecordHint, Val},
    },
    vault::record::{ChainRecord, ValidRecord},
};

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

mod record;
mod results;

pub use crate::vault::results::{DeleteRequest, ListResult, ReadRequest, ReadResult, Record, WriteRequest};

/// A view over the vault.  `key` is the Key used to lock the data. `chain` is a `ChainRecord` that contains all of the
/// associated records in the vault.  `valid` is a ValidRecord which contains only valid records.
#[derive(Serialize, Deserialize)]
pub struct DBView<P: BoxProvider> {
    key: Key<P>,
    chain: ChainRecord,
    valid: ValidRecord,
}

/// A reader for the `DBView`
pub struct DBReader<'a, P: BoxProvider> {
    view: &'a DBView<P>,
}

/// A writer for the `DBView`
pub struct DBWriter<P: BoxProvider> {
    view: DBView<P>,
    chain: ChainId, // TODO: change to RecordId
}

impl<P: BoxProvider> DBView<P> {
    /// Opens a vault using a key. Accepts the `ids` of the records that you want to load.
    pub fn load(key: Key<P>, ids: ListResult) -> crate::Result<Self> {
        // get records based on the Ids and open them with the key.
        let records = ids.into_iter()
            .filter_map(|bs| SealedTransaction::from(bs).decrypt(&key, b"").ok())
            .map(Record::new);

        // build indices
        let chain = ChainRecord::new(records)?;
        let valid = ValidRecord::new(&chain);

        Ok(Self { key, chain, valid })
    }

    /// Creates an iterator over all valid records. Iterates over ids and record hints
    pub fn records<'a>(&'a self) -> impl Iterator<Item = (ChainId, RecordHint)> + ExactSizeIterator + 'a {
        self.valid
            .all()
            .map(|e| e.force_typed::<DataTransaction>())
            .map(|d| (d.chain, d.record_hint))
    }

    /// Check the balance of valid records compared to total records
    pub fn absolute_balance(&self) -> (usize, usize) {
        (self.valid.all().count(), self.chain.all().count())
    }

    /// Get highest counter from the vault for known records
    // TODO: should these really be exposed
    pub fn chain_ctrs(&self) -> HashMap<ChainId, u64> {
        self.chain
            .chains()
            .map(|(id, _)| (*id, self.chain.force_last(id).ctr().u64()))
            .collect()
    }

    /// Check the age of the chains. Fills the `chain_ctr` with a HashMap of the chain's owner
    /// ids their counter size.
    pub fn not_older_than(&self, chain_ctrs: &HashMap<ChainId, u64>) -> crate::Result<()> {
        let this_ctrs = self.chain_ctrs();
        chain_ctrs.iter().try_for_each(|(chain, other_ctr)| {
            let this_ctr = this_ctrs.get(chain).ok_or_else(|| {
                crate::Error::VersionError(String::from("This database is older than the reference database"))
            })?;

            if this_ctr >= other_ctr {
                Ok(())
            } else {
                Err(crate::Error::VersionError(String::from(
                    "This database is older than the reference database",
                )))
            }
        })
    }

    /// Converts the `DBView` into a `DBReader`.
    pub fn reader(&self) -> DBReader<P> {
        DBReader { view: self }
    }

    /// Converts the `DBView` into a `DBWriter`.  Requires the owner's id as the `owned_chain`.
    pub fn writer(self, chain: ChainId) -> DBWriter<P> {
        DBWriter { view: self, chain }
    }
}

impl<'a, P: BoxProvider> DBReader<'a, P> {
    // TODO: ChainId:s => RecordId:s

    /// Prepare a record for reading. Create a `ReadRequest` to read the record with inputted `id`. Returns `None` if
    /// there was no record for that ID
    pub fn prepare_read(&self, id: ChainId) -> crate::Result<ReadRequest> {
        match self.view.valid.get(&id) {
            Some(r) => Ok(ReadRequest::payload::<P>(r.id())),
            _ => Err(crate::Error::InterfaceError),
        }
    }

    /// Open a record given a `ReadResult`.  Returns a vector of bytes.
    pub fn read(&self, res: ReadResult) -> crate::Result<Vec<u8>> {
        // reverse lookup
        let id = ChainId::load(res.id()).map_err(|_| crate::Error::InterfaceError)?;
        match self.view.valid.get(&id) {
            Some(e) => e.open_payload(&self.view.key, res.data()),
            _ => Err(crate::Error::InterfaceError),
        }
    }
}

fn seal_and_make_request<P: BoxProvider>(key: &Key<P>, tx: &Transaction) -> crate::Result<WriteRequest> {
    let ad = b""; // TODO: use the transaction id as an ad? is this already the case? results.rs:235?
    Ok(WriteRequest::transaction(&tx.untyped().id, &tx.encrypt(key, ad)?))
}

impl<P: BoxProvider> DBWriter<P> {

    /// create a new chain owned by owner.  Takes a secret `key` and the owner's `id` and creates a new
    /// `InitTransaction`.
    pub fn create_chain(key: &Key<P>, chain: ChainId) -> crate::Result<WriteRequest> {
        let id = TransactionId::random::<P>()?;
        let transaction = InitTransaction::new(chain, id, Val::from(0u64));
        seal_and_make_request(key, &transaction)
    }

    /// Check the balance of the amount of valid records compared to amount of total records in this chain
    pub fn relative_balance(&self) -> (usize, usize) {
        let valid = self.view.valid.all_for_chain(&self.chain).count();
        let all = self.view.chain.force_get(&self.chain).len();
        (valid, all)
    }

    /// Write the `data` to the chain. Generate a `DataTransaction` and return the record's `Id` along with a
    /// `WriteRequest`.
    pub fn write(self, data: &[u8], hint: RecordHint) -> crate::Result<(TransactionId, WriteRequest)> {
        let id = TransactionId::random::<P>()?;
        let ctr = self.view.chain.force_last(&self.chain).ctr() + 1;

        let transaction = DataTransaction::new(self.chain, ctr, id, hint);
        let req = seal_and_make_request(&self.view.key, &transaction)?;
        // TODO: handle the data
        Ok((id, req))
    }

    /// Revoke a record. Creates a revocation transaction for the given `id`.  Returns a `WriteRequest` and
    /// a `DeleteRequest`
    pub fn revoke(self) -> crate::Result<(WriteRequest, DeleteRequest)> {
        // check if id is still valid and get counter and transaction id
        let (start_ctr, id) = match self.view.valid.get(&self.chain) {
            Some(r) => (self.view.chain.force_last(&self.chain).ctr() + 1, r.id()),
            _ => return Err(crate::Error::InterfaceError),
        };

        let rid = TransactionId::random::<P>()?;
        let transaction = RevocationTransaction::new(self.chain, start_ctr, rid);
        let to_write = seal_and_make_request(&self.view.key, &transaction)?;
        let to_delete = DeleteRequest::new(id);
        Ok((to_write, to_delete))
    }

    /// Garbage Collect the records of a chain. create a new `InitTransaction` for an owned chain.  Returns
    /// `WriteRequests` and `DeleteRequests` of that chain.
    pub fn gc(self) -> crate::Result<(Vec<WriteRequest>, Vec<DeleteRequest>)> {
        // create InitTransaction
        let start_id = TransactionId::random::<P>()?;
        let start_ctr = self.view.chain.force_last(&self.chain).ctr() + 1;
        let start = InitTransaction::new(self.chain, start_id, start_ctr);
        let mut to_write = vec![seal_and_make_request(&self.view.key, &start)?];

        // locate revocation transactions
        let revoked: HashMap<_, _> = self.view.chain.own_revoked(&self.chain).collect();
        for data in self.view.chain.foreign_data(&self.chain) {
            if let Some(record) = revoked.get(&data.id()) {
                // clone and get view of transaction
                let mut transaction = record.transaction().clone();
                let view = transaction.force_typed_mut::<RevocationTransaction>();

                // update transaction and create transaction
                view.ctr = start_ctr + to_write.len() as u64;
                to_write.push(seal_and_make_request(&self.view.key, &transaction)?)
            }
        }

        // rebuild transactions and records data
        for record in self.view.valid.all_for_chain(&self.chain) {
            // create updated transaction
            let mut transaction = record.transaction().clone();
            let view = transaction.force_typed_mut::<DataTransaction>();
            view.ctr = start_ctr + to_write.len() as u64;

            // create the transaction
            to_write.push(seal_and_make_request(&self.view.key, &transaction)?);
        }
        // move init transaction to end.  Keeps the old chain valid until the new InitTransaction is written.
        to_write.rotate_left(1);

        // create a delete transction to delete all old and non-valid transactions
        let mut to_delete = Vec::new();
        for record in self.view.chain.force_get(&self.chain) {
            to_delete.push(DeleteRequest::new(record.id()));
        }
        Ok((to_write, to_delete))
    }

    /// take ownership of a chain with the owner id of `other`
    pub fn take_ownership(self, other: &ChainId) -> crate::Result<(Vec<WriteRequest>, Vec<DeleteRequest>)> {
        // get counters
        let this_ctr = self.view.chain.force_last(&self.chain).ctr() + 1;
        let other_ctr = self
            .view
            .chain
            .get(other)
            .map(|_| self.view.chain.force_last(other).ctr() + 1)
            .ok_or(crate::Error::InterfaceError)?;
        let mut to_write = Vec::new();

        // locate Revocation transaction
        let revoked: HashMap<_, _> = self.view.chain.own_revoked(other).collect();
        for data in self.view.chain.foreign_data(other) {
            if let Some(record) = revoked.get(&data.id()) {
                let this_ctr = this_ctr + to_write.len() as u64;
                let transaction = RevocationTransaction::new(self.chain, this_ctr, record.id());
                to_write.push(seal_and_make_request(&self.view.key, &transaction)?)
            }
        }

        // copy all valid transactions
        for record in self.view.valid.all_for_chain(other) {
            let this_ctr = this_ctr + to_write.len() as u64;
            let record = record.force_typed::<DataTransaction>();
            let transaction = DataTransaction::new(self.chain, this_ctr, record.id, record.record_hint);
            to_write.push(seal_and_make_request(&self.view.key, &transaction)?);
        }

        // create an InitTransaction
        let other_start_id = TransactionId::random::<P>()?;
        let other_start_transaction = InitTransaction::new(*other, other_start_id, other_ctr);
        to_write.push(seal_and_make_request(&self.view.key, &other_start_transaction)?);

        // delete the old transactions
        let mut to_delete = Vec::new();
        for record in self.view.chain.force_get(other) {
            to_delete.push(DeleteRequest::new(record.id()));
        }
        Ok((to_write, to_delete))
    }
}
