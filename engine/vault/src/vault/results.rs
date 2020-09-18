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
    types::{
        transactions::{SealedBlob, SealedTransaction},
        utils::{TransactionId, BlobId},
    },
};

use std::{
    vec::IntoIter,
};

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Kind {
    Transaction = 1,
    Blob = 2,
}

/// result of a list call
#[derive(Clone)]
pub struct ListResult {
    ids: Vec<Vec<u8>>,
}

/// a read call
#[derive(Clone)]
pub struct ReadRequest {
    kind: Kind,
    id: Vec<u8>,
}

/// a read result
#[derive(Clone)]
pub struct ReadResult {
    kind: Kind,
    id: Vec<u8>,
    data: Vec<u8>,
}

/// a write call
#[derive(Clone)]
pub struct WriteRequest {
    kind: Kind,
    id: Vec<u8>,
    data: Vec<u8>,
}

/// a delete call
#[derive(Clone)]
pub struct DeleteRequest {
    id: Vec<u8>,
}

impl ListResult {
    /// create new `ListResult` from a Vector of a Vector of Bytes.
    pub fn new(ids: Vec<Vec<u8>>) -> Self {
        Self { ids }
    }
    /// get the ids of the records
    pub fn ids(&self) -> &Vec<Vec<u8>> {
        &self.ids
    }
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

    pub fn result(&self, data: Vec<u8>) -> ReadResult {
        ReadResult {
            kind: self.kind,
            id: self.id.clone(),
            data,
        }
    }
}

impl ReadResult {
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

impl WriteRequest {
    /// create a write request for a transaction
    // TODO: a SealedTransaction should remember its id
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

    /// id of record
    pub fn id(&self) -> &[u8] {
        &self.id
    }

    /// data of record
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl DeleteRequest {
    /// create delete request by id
    pub(in crate) fn new(id: TransactionId) -> Self {
        Self {
            id: id.as_ref().to_vec(),
        }
    }

    /// get id of delete request
    pub fn id(&self) -> &[u8] {
        &self.id
    }
}

impl Into<Vec<Vec<u8>>> for ListResult {
    fn into(self) -> Vec<Vec<u8>> {
        self.ids
    }
}

impl IntoIterator for ListResult {
    type Item = Vec<u8>;
    type IntoIter = IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.ids.into_iter()
    }
}

impl Into<Vec<u8>> for ReadRequest {
    fn into(self) -> Vec<u8> {
        self.id
    }
}

impl Into<(Vec<u8>, Vec<u8>)> for ReadResult {
    fn into(self) -> (Vec<u8>, Vec<u8>) {
        (self.id, self.data)
    }
}

impl Into<(Vec<u8>, Vec<u8>)> for WriteRequest {
    fn into(self) -> (Vec<u8>, Vec<u8>) {
        (self.id, self.data)
    }
}

impl Into<Vec<u8>> for DeleteRequest {
    fn into(self) -> Vec<u8> {
        self.id
    }
}
