// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::types::{
    transactions::{SealedBlob, SealedTransaction},
    utils::{BlobId, TransactionId},
};

use serde::{Deserialize, Serialize};

use std::fmt::{self, Debug, Formatter};

use runtime::GuardedVec;

/// Enum that describes the type of a transaction.
#[derive(Copy, Clone, Hash, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub enum Kind {
    Transaction = 1,
    Blob = 2,
}

/// A read request call.  Contains the ID and Kind for the referred transaction.
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
            id: self.id.to_vec(),
            data: GuardedVec::new(data.len(), |i| i.copy_from_slice(data.as_ref())),
        }
    }
}

/// A Read Result which contains the data from the read request.  Contains the Kind, id and data of the transaction.
/// The data is guarded and needs to be unlocked and decrypted before it can be used.
#[derive(Clone, Serialize, Deserialize)]
pub struct ReadResult {
    kind: Kind,
    id: Vec<u8>,
    data: GuardedVec<u8>,
}

impl ReadResult {
    pub fn new(kind: Kind, id: &[u8], data: &[u8]) -> Self {
        Self {
            kind,
            id: id.to_vec(),
            data: GuardedVec::new(data.as_ref().len(), |i| i.copy_from_slice(data.as_ref())),
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
    pub(crate) fn data(&self) -> Vec<u8> {
        (*self.data.borrow()).to_vec()
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

/// A Write Request.  Contains the id, kind and data of the transaction that will be mutated.
#[derive(Clone)]
pub struct WriteRequest {
    kind: Kind,
    id: Vec<u8>,
    data: GuardedVec<u8>,
}

impl WriteRequest {
    /// create a write request for a transaction
    pub(in crate) fn transaction(id: &TransactionId, stx: &SealedTransaction) -> Self {
        Self {
            kind: Kind::Transaction,
            id: id.into(),
            data: GuardedVec::new(stx.as_ref().len(), |i| i.copy_from_slice(stx.as_ref())),
        }
    }

    /// creates a new request to write a blob
    pub(in crate) fn blob(id: &BlobId, sb: &SealedBlob) -> Self {
        Self {
            kind: Kind::Blob,
            id: id.into(),
            data: GuardedVec::new(sb.as_ref().len(), |i| i.copy_from_slice(sb.as_ref())),
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
    pub fn data(&self) -> Vec<u8> {
        (*self.data.borrow()).to_vec()
    }
}

/// A delete a transaction Request. Contains the id and Kind of the transaction to be revoked.
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
