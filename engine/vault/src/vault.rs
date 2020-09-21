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
    base64::Base64Encodable,
    crypto_box::{BoxProvider, Key, Encrypt, Decrypt},
    types::{
        transactions::{Transaction, DataTransaction, InitTransaction, RevocationTransaction, SealedTransaction, SealedBlob},
        utils::{BlobId, TransactionId, ChainId, RecordHint, Val},
    },
};

use serde::{Deserialize, Serialize};

use std::{
    fmt::{self, Debug, Formatter},
    convert::{TryFrom, TryInto},
    collections::HashMap,
};

mod chain;
mod results;

pub use crate::vault::results::{Kind, DeleteRequest, ReadRequest, ReadResult, WriteRequest};

/// A record identifier
#[repr(transparent)]
#[derive(Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecordId(ChainId);

impl Debug for RecordId {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Record({})", self.0.as_ref().base64())
    }
}

impl TryFrom<Vec<u8>> for RecordId {
    type Error = crate::Error;

    fn try_from(bs: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(RecordId(bs.try_into()?))
    }
}

impl TryFrom<&[u8]> for RecordId {
    type Error = crate::Error;

    fn try_from(bs: &[u8]) -> Result<Self, Self::Error> {
        Ok(RecordId(bs.try_into()?))
    }
}

impl RecordId {
    pub fn random<P: BoxProvider>() -> crate::Result<Self> {
        Ok(RecordId(ChainId::random::<P>()?))
    }
}

/// A view over the records in a vault
pub struct DBView<P: BoxProvider> {
    key: Key<P>,
    txs: HashMap<TransactionId, Transaction>,
    chains: HashMap<ChainId, chain::Chain>,
    cache: HashMap<BlobId, SealedBlob>,
}

impl<P: BoxProvider> DBView<P> {
    /// Opens a vault using a key. Accepts the `ReadResult`:s of the vault transactions you want to load.
    pub fn load<'a>(key: Key<P>, reads: impl Iterator<Item = &'a ReadResult>) -> crate::Result<Self> {
        let mut txs = HashMap::new();
        let mut raw_chains: HashMap<_, Vec<TransactionId>> = HashMap::new();
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
                    raw_chains.entry(tx.untyped().chain).or_default().push(id);
                    txs.insert(id, tx);
                },
                Kind::Blob => {
                    let id = BlobId::try_from(r.id())?;
                    cache.insert(id, SealedBlob::from(r.data()));
                },
            }
        }

        let mut chains = HashMap::new();
        for (cid, chain) in raw_chains.iter_mut() {
            chains.insert(*cid, chain::Chain::prune(chain.iter().filter_map(|t| txs.get(t)))?);
        }

        Ok(Self { key, txs, chains, cache })
    }

    /// Creates an iterator over all valid record identifiers and their corresponding record hints
    pub fn records<'a>(&'a self) -> impl Iterator<Item = (RecordId, RecordHint)> +  'a {
        self.chains.values().filter_map(move |r| {
            r.data()
                .as_ref()
                .and_then(|tx_id| self.txs.get(tx_id))
                .and_then(|tx| tx.typed::<DataTransaction>())
                .map(|tx| (RecordId(tx.chain), tx.record_hint))
        })
    }

    /// Check the balance of valid records compared to total records
    pub fn absolute_balance(&self) -> (usize, usize) {
        let mut balance = (0, 0);
        for r in self.chains.values() {
            balance.0 += r.balance().0;
            balance.1 += r.balance().1;
        }
        balance
    }

    /// Get highest counter from the vault for known records
    pub fn chain_ctrs(&self) -> HashMap<ChainId, u64> {
        self.chains.iter()
            .filter_map(|(id, r)| r.highest_ctr().map(|ctr| (*id, ctr.u64())))
            .collect()
    }

    /// Check the age of the records. Fills the `record_ctrs` with the records' oldest counter.
    pub fn not_older_than(&self, record_ctrs: &HashMap<RecordId, u64>) -> crate::Result<()> {
        let this_ctrs = self.chain_ctrs();
        record_ctrs.iter().try_for_each(|(chain, other_ctr)| {
            let this_ctr = this_ctrs.get(&chain.0).ok_or_else(|| {
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

    /// Converts the `DBView` into a `DBWriter` for a specific record.
    pub fn writer(&self, record: RecordId) -> DBWriter<P> {
        DBWriter { view: self, chain: record.0 }
    }

    /// Garbage collect the records.
    pub fn gc(&self) -> Vec<DeleteRequest> {
        // TODO: iterate through the blobs and check if any can be removed
        self.chains.values()
            .map(|r| r.garbage().iter().cloned().map(DeleteRequest::transaction))
            .flatten().collect()
    }
}

/// A reader for the `DBView`
pub struct DBReader<'a, P: BoxProvider> {
    view: &'a DBView<P>,
}

pub enum PreparedRead {
    CacheHit(Vec<u8>),
    CacheMiss(ReadRequest),
    RecordIsEmpty,
    NoSuchRecord,
}

impl<'a, P: BoxProvider> DBReader<'a, P> {
    /// Prepare a record for reading. Create a `ReadRequest` to read the record with inputted `id`. Returns `None` if
    /// there was no record for that ID
    pub fn prepare_read(&self, record: &RecordId) -> crate::Result<PreparedRead> {
        match self.view.chains.get(&record.0).map(|r| r.data()) {
            None => Ok(PreparedRead::NoSuchRecord),
            Some(None) => Ok(PreparedRead::RecordIsEmpty),
            Some(Some(tx_id)) => {
                // TODO: if we use references/boxes instead of ids then these never-failing lookups
                // can be removed
                let tx = self.view.txs.get(&tx_id).unwrap().typed::<DataTransaction>().unwrap();
                match self.view.cache.get(&tx.blob) {
                    Some(sb) => Ok(PreparedRead::CacheHit(sb.decrypt(&self.view.key, tx.blob)?)),
                    None => Ok(PreparedRead::CacheMiss(ReadRequest::blob(tx.blob)))
                }
            }
        }
    }

    /// Open a record given a `ReadResult`.  Returns a vector of bytes.
    pub fn read(&self, res: ReadResult) -> crate::Result<Vec<u8>> {
        // TODO: add parameter to allow the vault to cache the result
        let b = BlobId::try_from(res.id())?;
        // TODO: reverse lookup blob id to chain id, compare with the valid transaction's blob id
        SealedBlob::from(res.data()).decrypt(&self.view.key, b)
    }

    pub fn exists(&self, id: RecordId) -> bool {
        match self.view.chains.get(&id.0).map(|r| r.init()) {
            None => false,
            Some(None) => false,
            Some(Some(_)) => true,
        }
    }
}

/// A writer for the `DBView`
pub struct DBWriter<'a, P: BoxProvider> {
    view: &'a DBView<P>,
    chain: ChainId,
}

impl<'a, P: BoxProvider> DBWriter<'a, P> {
    fn next_ctr(&self) -> Val {
        self.view.chains.get(&self.chain)
            .and_then(|r| r.highest_ctr())
            .map(|ctr| ctr + 1).unwrap_or(0u64.into())
    }

    /// Create a new empty record or truncate an existing one
    pub fn truncate(&self) -> crate::Result<WriteRequest> {
        let id = TransactionId::random::<P>()?;
        let tx = InitTransaction::new(self.chain, id, self.next_ctr());
        Ok(WriteRequest::transaction(&id, &tx.encrypt(&self.view.key, id)?))
    }

    /// Check the balance of the amount of valid records compared to amount of total records in this chain
    pub fn relative_balance(&self) -> (usize, usize) {
        match self.view.chains.get(&self.chain) {
            Some(c) => c.balance(),
            None => (0, 0)
        }
    }

    /// Write the `data` to the record, replaces existing data and undoes uncommitted revokes.
    pub fn write(&self, data: &[u8], hint: RecordHint) -> crate::Result<Vec<WriteRequest>> {
        let tx_id = TransactionId::random::<P>()?;
        let blob_id = BlobId::random::<P>()?;
        let transaction = DataTransaction::new(self.chain, self.next_ctr(), tx_id, blob_id, hint);

        let req = WriteRequest::transaction(&tx_id, &transaction.encrypt(&self.view.key, tx_id)?);
        let blob = WriteRequest::blob(&blob_id, &data.encrypt(&self.view.key, blob_id)?);

        Ok(vec![req, blob])
    }

    /// Revoke a record.
    pub fn revoke(self) -> crate::Result<WriteRequest> {
        let id = TransactionId::random::<P>()?;
        let tx = RevocationTransaction::new(self.chain, self.next_ctr(), id);
        Ok(WriteRequest::transaction(&id, &tx.encrypt(&self.view.key, id)?))
    }
}
