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
        transactions::{Transaction, DataTransaction, InitTransaction, RevocationTransaction, SealedTransaction, SealedBlob},
        utils::{BlobId, TransactionId, ChainId, RecordHint, Val},
    },
    vault::record::{ChainRecord},
};

use std::{
    convert::TryFrom,
    collections::HashMap,
};

mod record;
mod results;

pub use crate::vault::results::{Kind, DeleteRequest, ListResult, ReadRequest, ReadResult, Record, WriteRequest};

/// A view over the vault.  `key` is the Key used to lock the data. `chain` is a `ChainRecord` that contains all of the
/// associated records in the vault.  `valid` is a ValidRecord which contains only valid records.
pub struct DBView<P: BoxProvider> {
    key: Key<P>,
    chain: ChainRecord,
    valid: HashMap<ChainId, TransactionId>,
    cache: HashMap<BlobId, SealedBlob>,
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
    pub fn load(key: Key<P>, reads: impl Iterator<Item = ReadResult>) -> crate::Result<Self> {
        let mut txs: Vec<Record> = vec![];
        let mut cache = HashMap::new();

        for r in reads {
            match r.kind() {
                Kind::Transaction => {
                    let id = TransactionId::try_from(r.id())?;
                    let tx = SealedTransaction::from(r.data()).decrypt(&key, r.id())?;
                    if id != tx.untyped().id {
                        // TODO: more precise error w/ the failing transaction id
                        return Err(crate::Error::InterfaceError)
                    }
                    txs.push(Record::new(tx));
                },
                Kind::Blob => {
                    let id = BlobId::try_from(r.id())?;
                    cache.insert(id, SealedBlob::from(r.data()));
                },
            }
        }

        let chain = ChainRecord::new(txs.iter())?;

        let mut valid = HashMap::new();
        for tx in chain.all() {
            if let Some(dtx) = tx.typed::<DataTransaction>() {
                valid.insert(dtx.chain, dtx.id);
            }
        }
        for tx in chain.all() {
            if let Some(rtx) = tx.typed::<RevocationTransaction>() {
                valid.remove(&rtx.chain);
            }
        }

        Ok(Self { key, chain, valid, cache })
    }

    fn lookup(&self, c_id: &ChainId, tx_id: &TransactionId) -> Option<&DataTransaction> {
        // TODO: keep a HashMap<TransactionId, Transaction> and let chain be a
        // Map<ChainId, Vec<TransactionId>>?
        self.chain.get(c_id).and_then(|txs| {
            txs.iter().find(|tx| tx.id() == *tx_id)
                .and_then(|tx| tx.typed::<DataTransaction>())
        })
    }

    /// Creates an iterator over all valid records. Iterates over ids and record hints
    pub fn records<'a>(&'a self) -> impl Iterator<Item = (ChainId, RecordHint)> +  'a {
        self.valid.iter().filter_map(move |(c_id, tx_id)| {
            self.lookup(c_id, tx_id).map(|tx| (tx.chain, tx.record_hint))
        })
    }

    /// Check the balance of valid records compared to total records
    pub fn absolute_balance(&self) -> (usize, usize) {
        (self.valid.len(), self.chain.all().count())
    }

    /// Get highest counter from the vault for known records
    // TODO: should these really be exposed?
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
    pub fn prepare_read(&self, c_id: &ChainId) -> crate::Result<ReadRequest> {
        match self.view.valid.get(&c_id).and_then(|tx_id| self.view.lookup(c_id, tx_id)) {
            Some(dtx) => Ok(ReadRequest::blob(dtx.blob)),
            _ => Err(crate::Error::InterfaceError),
        }
    }

    /// Open a record given a `ReadResult`.  Returns a vector of bytes.
    pub fn read(&self, res: ReadResult) -> crate::Result<Vec<u8>> {
        let b = BlobId::try_from(res.id())?;
        // TODO: reverse lookup blob id to chain id, compare with the valid transaction's blob id
        SealedBlob::from(res.data()).decrypt(&self.view.key, b)
    }
}

fn seal_and_make_request<P: BoxProvider>(key: &Key<P>, tx: &Transaction) -> crate::Result<WriteRequest> {
    let id = tx.untyped().id;
    Ok(WriteRequest::transaction(&id, &tx.encrypt(key, id)?))
}

impl<P: BoxProvider> DBWriter<P> {
    /// create a new chain owned by owner.  Takes a secret `key` and the owner's `id` and creates a new
    /// `InitTransaction`.
    pub fn create_chain(key: &Key<P>, chain: ChainId) -> crate::Result<WriteRequest> {
        let id = TransactionId::random::<P>()?;
        let tx = InitTransaction::new(chain, id, Val::from(0u64));
        Ok(WriteRequest::transaction(&id, &tx.encrypt(key, id)?))
    }

    /// Check the balance of the amount of valid records compared to amount of total records in this chain
    pub fn relative_balance(&self) -> (usize, usize) {
        unimplemented!("TODO: what does this mean?")
    }

    /// Write the `data` to the chain. Generate a `DataTransaction` and return the record's `Id` along with a
    /// `WriteRequest`.
    pub fn write(self, data: &[u8], hint: RecordHint) -> crate::Result<Vec<WriteRequest>> {
        let tx_id = TransactionId::random::<P>()?;
        let blob_id = BlobId::random::<P>()?;
        let ctr = self.view.chain.force_last(&self.chain).ctr() + 1;
        let transaction = DataTransaction::new(self.chain, ctr, tx_id, blob_id, hint);

        let req = WriteRequest::transaction(&tx_id, &transaction.encrypt(&self.view.key, tx_id)?);
        let blob = WriteRequest::blob(&blob_id, &data.encrypt(&self.view.key, blob_id)?);

        Ok(vec![req, blob])
    }

    /// Revoke a record. Creates a revocation transaction for the given `id`.  Returns a `WriteRequest` and
    /// a `DeleteRequest`
    pub fn revoke(self) -> crate::Result<(WriteRequest, DeleteRequest)> {
        // check if id is still valid and get counter and transaction id
        let (start_ctr, id) = match self.view.valid.get(&self.chain) {
            Some(id) => (self.view.chain.force_last(&self.chain).ctr() + 1, id),
            _ => return Err(crate::Error::InterfaceError),
        };

        let rid = TransactionId::random::<P>()?;
        let transaction = RevocationTransaction::new(self.chain, start_ctr, rid);
        let to_write = seal_and_make_request(&self.view.key, &transaction)?;
        let to_delete = DeleteRequest::new(*id);
        Ok((to_write, to_delete))
    }

    /// Garbage Collect the records of a chain. create a new `InitTransaction` for an owned chain.  Returns
    /// `WriteRequests` and `DeleteRequests` of that chain.
    pub fn gc(self) -> crate::Result<(Vec<WriteRequest>, Vec<DeleteRequest>)> {
        // TODO: review and cover with unit tests

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
        for (c_id, tx_id) in self.view.valid.iter() {
            if let Some(tx) = self.view.lookup(c_id, tx_id) {
                let ctr = start_ctr + to_write.len() as u64;
                // TODO: better/clearer way of serializing the transaction
                let id = tx.id;
                let tx = DataTransaction::new(tx.chain, ctr, id, tx.blob, tx.record_hint);
                let ct = tx.encrypt(&self.view.key, id)?;
                to_write.push(WriteRequest::transaction(&id, &ct));
            }
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
        for (c_id, tx_id) in self.view.valid.iter() {
            if let Some(tx) = self.view.lookup(c_id, tx_id) {
                let this_ctr = this_ctr + to_write.len() as u64;

                // TODO: better/clearer way of serializing the transaction
                let id = tx.id;
                let tx = DataTransaction::new(tx.chain, this_ctr, id, tx.blob, tx.record_hint);
                let ct = tx.encrypt(&self.view.key, id)?;
                to_write.push(WriteRequest::transaction(&id, &ct));
            }
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
