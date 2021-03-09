// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::types::{
    transactions::{SealedBlob, SealedTransaction},
    utils::{BlobId, TransactionId},
};

use serde::{Deserialize, Serialize};

use std::fmt::{self, Debug, Formatter};

use runtime::GuardedVec;

#[derive(Copy, Clone, Hash, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub enum Kind {
    Transaction = 1,
    Blob = 2,
}

/// a read call
#[derive(Clone, PartialEq, Eq)]
pub struct ReadRequest {
    kind: Kind,
    id: Vec<u8>,
}

impl ReadRequest {
    /// create a read request for a transaction
    pub fn transaction(id: TransactionId) -> Self {
        Self {
            kind: Kind::Transaction,
            id: id.as_ref().to_vec(),
        }
    }

    /// create a read request for a transaction
    pub fn blob(id: BlobId) -> Self {
        Self {
            kind: Kind::Blob,
            id: id.into(),
        }
    }

    /// id of a record
    pub fn id(&self) -> &[u8] {
        &self.id
    }

    /// kind of data
    pub fn kind(&self) -> Kind {
        self.kind
    }

    pub fn result(&self, data: Vec<u8>) -> ReadResult {
        ReadResult {
            kind: self.kind,
            id: self.id.clone(),
            data,
        }
    }
}

/// a read result
#[derive(Clone)]
pub struct ReadResult {
    kind: Kind,
    id: Vec<u8>,
    data: Vec<u8>,
}

impl ReadResult {
    pub fn new(kind: Kind, id: &[u8], data: &[u8]) -> Self {
        Self {
            kind,
            id: id.to_vec(),
            data: data.to_vec(),
        }
    }

    /// id of read result
    pub fn id(&self) -> &[u8] {
        &self.id
    }

    /// kind of data
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// data from record
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl AsRef<ReadResult> for ReadResult {
    fn as_ref(&self) -> &Self {
        &self
    }
}

impl Debug for ReadResult {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "ReadResult")
    }
}

/// a write call
#[derive(Clone)]
pub struct WriteRequest {
    kind: Kind,
    id: Vec<u8>,
    data: Vec<u8>,
}

impl WriteRequest {
    /// create a write request for a transaction
    pub(in crate) fn transaction(id: &TransactionId, stx: &SealedTransaction) -> Self {
        Self {
            kind: Kind::Transaction,
            id: id.into(),
            data: stx.as_ref().to_vec(),
        }
    }

    /// creates a new request to write a blob
    pub(in crate) fn blob(id: &BlobId, sb: &SealedBlob) -> Self {
        Self {
            kind: Kind::Blob,
            id: id.into(),
            data: sb.as_ref().to_vec(),
        }
    }

    /// id of entity
    pub fn id(&self) -> &[u8] {
        &self.id
    }

    /// kind of data
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// data of record
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// a delete call
#[derive(Clone)]
pub struct DeleteRequest {
    kind: Kind,
    id: Vec<u8>,
}

impl DeleteRequest {
    /// create delete request by transaction id
    pub(in crate) fn transaction(id: TransactionId) -> Self {
        Self {
            kind: Kind::Transaction,
            id: id.as_ref().to_vec(),
        }
    }

    /// get id of delete request
    pub fn id(&self) -> &[u8] {
        &self.id
    }

    /// kind of data
    pub fn kind(&self) -> Kind {
        self.kind
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct GuardedData {
    kind: u8,
    id: GuardedVec<u8>,
    data: GuardedVec<u8>,
}

impl From<GuardedData> for ReadResult {
    fn from(guard: GuardedData) -> Self {
        let kind = match guard.kind {
            1 => Kind::Transaction,
            2 => Kind::Blob,
            // Impossible since kind can only be 1 or 2.
            _ => panic!("Invalid Kind"),
        };

        let data = (*guard.data.borrow()).to_vec();
        let id = (*guard.id.borrow()).to_vec();

        ReadResult { kind, data, id }
    }
}

impl From<ReadResult> for GuardedData {
    fn from(res: ReadResult) -> Self {
        let kind = match res.kind {
            Kind::Transaction => 1,
            Kind::Blob => 2,
        };

        let data = GuardedVec::new(res.data.len(), |d| d.copy_from_slice(res.data.as_slice()));
        let id = GuardedVec::new(res.id.len(), |d| d.copy_from_slice(res.id.as_slice()));

        GuardedData { kind, id, data }
    }
}

impl Debug for GuardedData {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "GuardedData")
    }
}
