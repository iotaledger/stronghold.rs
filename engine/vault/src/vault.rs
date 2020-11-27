// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    base64::Base64Encodable,
    crypto_box::{BoxProvider, Decrypt, Encrypt, Key},
    types::{
        transactions::{
            DataTransaction, InitTransaction, RevocationTransaction, SealedBlob, SealedTransaction, Transaction,
        },
        utils::{BlobId, ChainId, RecordHint, TransactionId, Val},
    },
};

use serde::{Deserialize, Serialize};

use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    fmt::{self, Debug, Display, Formatter},
};

mod chain;
mod protocol;

pub use crate::vault::protocol::{DeleteRequest, Kind, ReadRequest, ReadResult, WriteRequest};

/// A record identifier
#[repr(transparent)]
#[derive(Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecordId(ChainId);

impl Debug for RecordId {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Record({})", self.0.as_ref().base64())
    }
}

impl Display for RecordId {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.0.as_ref().base64())
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
    blobs: HashMap<BlobId, Vec<TransactionId>>,
    cache: HashMap<BlobId, SealedBlob>,
}

impl<P: BoxProvider> DBView<P> {
    /// Opens a vault using a key. Accepts the `ReadResult`:s of the vault transactions you want to load.
    pub fn load<R: AsRef<ReadResult>>(key: Key<P>, reads: impl Iterator<Item = R>) -> crate::Result<Self> {
        let mut txs = HashMap::new();
        let mut raw_chains: HashMap<_, Vec<TransactionId>> = HashMap::new();
        let mut cache = HashMap::new();
        let mut blobs: HashMap<_, Vec<_>> = HashMap::new();

        for r in reads {
            let r = r.as_ref();
            match r.kind() {
                Kind::Transaction => {
                    let id = TransactionId::try_from(r.id())?;
                    let tx = SealedTransaction::from(r.data()).decrypt(&key, r.id())?;
                    if id != tx.untyped().id {
                        // TODO: more precise error w/ the failing transaction id
                        return Err(crate::Error::InterfaceError);
                    }

                    if let Some(dtx) = tx.typed::<DataTransaction>() {
                        blobs.entry(dtx.blob).or_default().push(id);
                    }

                    raw_chains.entry(tx.untyped().chain).or_default().push(id);
                    txs.insert(id, tx);
                }
                Kind::Blob => {
                    let id = BlobId::try_from(r.id())?;
                    cache.insert(id, SealedBlob::from(r.data()));
                    blobs.entry(id).or_default();
                }
            }
        }

        let mut chains = HashMap::new();
        for (cid, chain) in raw_chains.iter_mut() {
            chains.insert(*cid, chain::Chain::prune(chain.iter().filter_map(|t| txs.get(t)))?);
        }

        Ok(Self {
            key,
            txs,
            chains,
            blobs,
            cache,
        })
    }

    /// Creates an iterator over all valid record identifiers and their corresponding record hints
    pub fn records<'a>(&'a self) -> impl Iterator<Item = (RecordId, RecordHint)> + 'a {
        self.chains.values().filter_map(move |r| {
            r.data()
                .as_ref()
                .and_then(|tx_id| self.txs.get(tx_id))
                .and_then(|tx| tx.typed::<DataTransaction>())
                .map(|tx| (RecordId(tx.chain), tx.record_hint))
        })
    }

    /// Creates an iterator over all valid records ids.
    pub fn all<'a>(&'a self) -> impl ExactSizeIterator<Item = RecordId> + 'a {
        self.chains.keys().map(|k| RecordId(*k))
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
    pub fn chain_ctrs(&self) -> HashMap<RecordId, u64> {
        self.chains
            .iter()
            .filter_map(|(id, r)| r.highest_ctr().map(|ctr| (RecordId(*id), ctr.u64())))
            .collect()
    }

    /// Check the age of the records. Fills the `record_ctrs` with the records' oldest counter.
    pub fn not_older_than(&self, record_ctrs: &HashMap<RecordId, u64>) -> crate::Result<()> {
        let this_ctrs = self.chain_ctrs();
        record_ctrs.iter().try_for_each(|(chain, other_ctr)| {
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

    /// Converts the `DBView` into a `DBWriter` for a specific record.
    pub fn writer(&self, record: RecordId) -> DBWriter<P> {
        let next_ctr = self
            .chains
            .get(&record.0)
            .and_then(|r| r.highest_ctr())
            .map(|v| v + 1)
            .unwrap_or_else(|| 0u64.into());

        DBWriter {
            view: self,
            chain: record.0,
            next_ctr,
        }
    }

    /// Garbage collect the records.
    pub fn gc(&self) -> Vec<DeleteRequest> {
        // TODO: iterate through the blobs and check if any can be removed
        self.chains
            .values()
            .map(|r| r.garbage().iter().cloned().map(DeleteRequest::transaction))
            .flatten()
            .collect()
    }
}

impl<P: BoxProvider> Debug for DBView<P> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let cs: HashMap<_, Vec<_>> = self
            .chains
            .iter()
            .map(|(cid, c)| (cid, c.subchain().iter().filter_map(|tx| self.txs.get(tx)).collect()))
            .collect();
        let garbage: Vec<_> = self
            .chains
            .values()
            .map(|c| c.garbage().iter().filter_map(|tx| self.txs.get(tx)))
            .flatten()
            .collect();
        f.debug_struct("DBView")
            .field("chains", &cs)
            .field("garbage", &garbage)
            .finish()
    }
}

/// A reader for the `DBView`
pub struct DBReader<'a, P: BoxProvider> {
    view: &'a DBView<P>,
}

#[derive(Eq, PartialEq)]
pub enum PreparedRead {
    CacheHit(Vec<u8>),
    CacheMiss(ReadRequest),
    RecordIsEmpty,
    NoSuchRecord,
}

impl Debug for PreparedRead {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            PreparedRead::CacheHit(_) => f.write_str("PreparedRead::CacheHit"),
            PreparedRead::CacheMiss(_) => f.write_str("PreparedRead::CacheMiss"),
            PreparedRead::RecordIsEmpty => f.write_str("PreparedRead::RecordIsEmpty"),
            PreparedRead::NoSuchRecord => f.write_str("PreparedRead::NoSuchRecord"),
        }
    }
}

impl<'a, P: BoxProvider> DBReader<'a, P> {
    /// Prepare a record for reading. Create a `ReadRequest` to read the record with inputted `id`. Returns `None` if
    /// there was no record for that ID
    pub fn prepare_read(&self, record: &RecordId) -> crate::Result<PreparedRead> {
        match self.view.chains.get(&record.0).map(|r| (r.init(), r.data())) {
            None | Some((None, _)) => Ok(PreparedRead::NoSuchRecord),
            Some((_, None)) => Ok(PreparedRead::RecordIsEmpty),
            Some((_, Some(tx_id))) => {
                // TODO: if we use references/boxes instead of ids then these never-failing lookups
                // can be removed
                let tx = self.view.txs.get(&tx_id).unwrap().typed::<DataTransaction>().unwrap();
                match self.view.cache.get(&tx.blob) {
                    Some(sb) => Ok(PreparedRead::CacheHit(sb.decrypt(&self.view.key, tx.blob)?)),
                    None => Ok(PreparedRead::CacheMiss(ReadRequest::blob(tx.blob))),
                }
            }
        }
    }

    /// Open a record given a `ReadResult`.  Returns a vector of bytes.
    pub fn read(&self, res: ReadResult) -> crate::Result<Vec<u8>> {
        // TODO: add parameter to allow the vault to cache the result
        let b = BlobId::try_from(res.id())?;

        if self.is_active_blob(&b) {
            SealedBlob::from(res.data()).decrypt(&self.view.key, b)
        } else {
            Err(crate::Error::ProtocolError("invalid blob".to_string()))
        }
    }

    fn is_active_blob(&self, bid: &BlobId) -> bool {
        self.view
            .blobs
            .get(bid)
            .map(|txs| {
                txs.iter().any(|t0| {
                    self.view
                        .txs
                        .get(t0)
                        .and_then(|tx| tx.typed::<DataTransaction>())
                        .and_then(|tx| if tx.blob == *bid { Some(tx.chain) } else { None })
                        .and_then(|cid| self.view.chains.get(&cid))
                        .and_then(|c| c.data())
                        .map(|t1| *t0 == t1)
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
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
    next_ctr: Val,
}

impl<'a, P: BoxProvider> DBWriter<'a, P> {
    fn next_ctr(&mut self) -> Val {
        let c = self.next_ctr;
        self.next_ctr += 1;
        c
    }

    /// Create a new empty record or truncate an existing one
    pub fn truncate(&mut self) -> crate::Result<WriteRequest> {
        let id = TransactionId::random::<P>()?;
        let tx = InitTransaction::new(self.chain, id, self.next_ctr());
        Ok(WriteRequest::transaction(&id, &tx.encrypt(&self.view.key, id)?))
    }

    /// Check the balance of the amount of valid records compared to amount of total records in this chain
    pub fn relative_balance(&self) -> (usize, usize) {
        match self.view.chains.get(&self.chain) {
            Some(c) => c.balance(),
            None => (0, 0),
        }
    }

    /// Write the `data` to the record, replaces existing data and undoes uncommitted revokes.
    pub fn write(&mut self, data: &[u8], hint: RecordHint) -> crate::Result<Vec<WriteRequest>> {
        let tx_id = TransactionId::random::<P>()?;
        let blob_id = BlobId::random::<P>()?;
        let transaction = DataTransaction::new(self.chain, self.next_ctr(), tx_id, blob_id, hint);

        let req = WriteRequest::transaction(&tx_id, &transaction.encrypt(&self.view.key, tx_id)?);
        let blob = WriteRequest::blob(&blob_id, &data.encrypt(&self.view.key, blob_id)?);

        Ok(vec![req, blob])
    }

    /// Revoke a record.
    pub fn revoke(&mut self) -> crate::Result<WriteRequest> {
        let id = TransactionId::random::<P>()?;
        let tx = RevocationTransaction::new(self.chain, self.next_ctr(), id);
        Ok(WriteRequest::transaction(&id, &tx.encrypt(&self.view.key, id)?))
    }
}
