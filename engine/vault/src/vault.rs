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
    crypto_box::{BoxProvider, Key},
    types::{
        transactions::{DataTransaction, InitTransaction, RevocationTransaction},
        utils::{Id, RecordHint, Val},
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
    owner: Id,
}

impl<P: BoxProvider> DBView<P> {
    /// Opens a vault using a key. Accepts the `ids` of the records that you want to load.  
    pub fn load(key: Key<P>, ids: ListResult) -> crate::Result<Self> {
        // get records based on the Ids and open them with the key.
        let records = ids.into_iter().filter_map(|id| Record::open(&key, &id));

        // build indices
        let chain = ChainRecord::new(records)?;
        let valid = ValidRecord::new(&chain);

        Ok(Self { key, chain, valid })
    }

    /// Creates an iterator over all valid records. Iterates over ids and record hints
    pub fn records<'a>(&'a self) -> impl Iterator<Item = (Id, RecordHint)> + ExactSizeIterator + 'a {
        self.valid
            .all()
            .map(|e| e.force_typed::<DataTransaction>())
            .map(|d| (d.id, d.record_hint))
    }

    /// Creates an iterator over all valid records ids.
    pub fn all<'a>(&'a self) -> impl Iterator<Item = Id> + 'a {
        self.chain
            .all()
            .filter_map(|e| e.typed::<DataTransaction>())
            .map(|d| d.id)
    }

    /// Check the balance of valid records compared to total records
    pub fn absolute_balance(&self) -> (usize, usize) {
        (self.valid.all().count(), self.chain.all().count())
    }

    /// Get highest counter from the vault.
    pub fn chain_ctrs(&self) -> HashMap<Id, u64> {
        self.chain
            .owners()
            .map(|(owner, _)| (*owner, self.chain.force_last(owner).ctr().u64()))
            .collect()
    }

    /// Check the age of the chains. Fills the `chain_ctr` with a HashMap of the chain's owner
    /// ids their counter size.
    pub fn not_older_than(&self, chain_ctrs: &HashMap<Id, u64>) -> crate::Result<()> {
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
    pub fn writer(self, owned_chain: Id) -> DBWriter<P> {
        DBWriter {
            view: self,
            owner: owned_chain,
        }
    }
}

impl<'a, P: BoxProvider> DBReader<'a, P> {
    /// Prepare a record for reading. Create a `ReadRequest` to read the record with inputted `id`. Returns `None` if
    /// there was no record for that ID
    pub fn prepare_read(&self, id: Id) -> crate::Result<ReadRequest> {
        match self.view.valid.get(&id) {
            Some(_) => Ok(ReadRequest::payload::<P>(id)),
            _ => Err(crate::Error::InterfaceError),
        }
    }

    /// Open a record given a `ReadResult`.  Returns a vector of bytes.
    pub fn read(&self, res: ReadResult) -> crate::Result<Vec<u8>> {
        // reverse lookup
        let id = Id::load(res.id()).map_err(|_| crate::Error::InterfaceError)?;
        match self.view.valid.get(&id) {
            Some(e) => e.open_payload(&self.view.key, res.data()),
            _ => Err(crate::Error::InterfaceError),
        }
    }
}

impl<P: BoxProvider> DBWriter<P> {
    /// create a new chain owned by owner.  Takes a secret `key` and the owner's `id` and creates a new
    /// `InitTransaction`.
    pub fn create_chain(key: &Key<P>, owner: Id) -> WriteRequest {
        let transaction = InitTransaction::new(owner, Val::from(0u64));
        Record::new(key, transaction).write()
    }

    /// Check the balance of the amount of valid records compared to amount of total records in this chain
    pub fn relative_balance(&self) -> (usize, usize) {
        let valid = self.view.valid.all_for_owner(&self.owner).count();
        let all = self.view.chain.force_get(&self.owner).len();
        (valid, all)
    }

    /// Write the `data` to the chain. Generate a `DataTransaction` and return the record's `Id` along with a
    /// `WriteRequest`.
    pub fn write(self, data: &[u8], hint: RecordHint) -> crate::Result<(Id, Vec<WriteRequest>)> {
        // generate id
        let id = Id::random::<P>()?;
        // get counter
        let ctr = self.view.chain.force_last(&self.owner).ctr() + 1;

        // create transaction
        let transaction = DataTransaction::new(self.owner, ctr, id, hint);
        // create record
        let record = Record::new(&self.view.key, transaction);
        Ok((id, record.write_payload(&self.view.key, data)?))
    }

    /// Revoke a record. Creates a revocation transaction for the given `id`.  Returns a `WriteRequest` and
    /// a `DeleteRequest`
    pub fn revoke(self, id: Id) -> crate::Result<(WriteRequest, DeleteRequest)> {
        // check if id is still valid and get counter
        let start_ctr = match self.view.valid.get(&id) {
            Some(_) => self.view.chain.force_last(&self.owner).ctr() + 1,
            _ => return Err(crate::Error::InterfaceError),
        };

        // generate transaction
        let transaction = RevocationTransaction::new(self.owner, start_ctr, id);
        // generate record
        let to_write = Record::new(&self.view.key, transaction).write();
        // create delete request
        let to_delete = DeleteRequest::uid(id);
        Ok((to_write, to_delete))
    }

    /// Garbage Collect the records of a chain. create a new `InitTransaction` for an owned chain.  Returns
    /// `WriteRequests` and `DeleteRequests` of that chain.
    pub fn gc(self) -> crate::Result<(Vec<WriteRequest>, Vec<DeleteRequest>)> {
        // create InitTransaction
        let start_ctr = self.view.chain.force_last(&self.owner).ctr() + 1;
        let start = InitTransaction::new(self.owner, start_ctr);
        let mut to_write = vec![Record::new(&self.view.key, start).write()];

        // locate revocation transactions
        let revoked: HashMap<_, _> = self.view.chain.own_revoked(&self.owner).collect();
        for data in self.view.chain.foreign_data(&self.owner) {
            if let Some(record) = revoked.get(&data.force_uid()) {
                // clone and get view of transaction
                let mut transaction = record.transaction().clone();
                let view = transaction.force_typed_mut::<RevocationTransaction>();

                // update transaction and create transaction
                view.ctr = start_ctr + to_write.len() as u64;
                to_write.push(Record::new(&self.view.key, transaction).write())
            }
        }

        // rebuild transactions and records data
        for record in self.view.valid.all_for_owner(&self.owner) {
            // create updated transaction
            let mut transaction = record.transaction().clone();
            let view = transaction.force_typed_mut::<DataTransaction>();
            view.ctr = start_ctr + to_write.len() as u64;

            // create the transaction
            to_write.push(Record::new(&self.view.key, transaction).write());
        }
        // move init transaction to end.  Keeps the old chain valid until the new InitTransaction is written.
        to_write.rotate_left(1);

        // create a delete transction to delete all old and non-valid transactions
        let mut to_delete = Vec::new();
        for record in self.view.chain.force_get(&self.owner) {
            to_delete.push(DeleteRequest::transaction(record.sealed()));
        }
        Ok((to_write, to_delete))
    }

    /// take ownership of a chain with the owner id of `other`
    pub fn take_ownership(self, other: &Id) -> crate::Result<(Vec<WriteRequest>, Vec<DeleteRequest>)> {
        // get counters
        let this_ctr = self.view.chain.force_last(&self.owner).ctr() + 1;
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
            if let Some(record) = revoked.get(&data.force_uid()) {
                let this_ctr = this_ctr + to_write.len() as u64;
                let transaction = RevocationTransaction::new(self.owner, this_ctr, record.force_uid());
                to_write.push(Record::new(&self.view.key, transaction).write())
            }
        }

        // copy all valid transactions
        for record in self.view.valid.all_for_owner(other) {
            let this_ctr = this_ctr + to_write.len() as u64;
            let record = record.force_typed::<DataTransaction>();
            let transaction = DataTransaction::new(self.owner, this_ctr, record.id, record.record_hint);
            to_write.push(Record::new(&self.view.key, transaction).write());
        }

        // create an InitTransaction
        let other_start_transaction = InitTransaction::new(*other, other_ctr);
        to_write.push(Record::new(&self.view.key, other_start_transaction).write());

        // delete the old transactions
        let mut to_delete = Vec::new();
        for record in self.view.chain.force_get(other) {
            to_delete.push(DeleteRequest::transaction(record.sealed()));
        }
        Ok((to_write, to_delete))
    }
}
