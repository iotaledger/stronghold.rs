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

use crate::types::{
    transactions::{SealedBlob, SealedTransaction},
    utils::{BlobId, TransactionId},
};

use serde::{Deserialize, Serialize};

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
#[derive(Clone, Serialize, Deserialize)]
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
