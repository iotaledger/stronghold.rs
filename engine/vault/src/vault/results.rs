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
    crypto_box::{BoxProvider, Decrypt, Key},
    types::{
        transactions::{
            DataTransaction, InitTransaction, RevocationTransaction, SealedPayload, SealedTransaction, Transaction,
            TypedTransaction,
        },
        utils::{ChainId, TransactionId, Val},
        AsView,
    },
};

use std::{
    fmt::{self, Debug, Formatter},
    vec::IntoIter,
};

use serde::{Deserialize, Serialize};

/// result of a list call
#[derive(Clone)]
pub struct ListResult {
    ids: Vec<Vec<u8>>,
}

/// a read call
#[derive(Clone)]
pub struct ReadRequest {
    id: Vec<u8>,
}

/// a read result
#[derive(Clone)]
pub struct ReadResult {
    id: Vec<u8>,
    data: Vec<u8>,
}

/// a write call
#[derive(Clone)]
pub struct WriteRequest {
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
    /// create a new read request
    pub fn payload<P: BoxProvider>(id: TransactionId) -> Self {
        Self {
            id: id.as_ref().to_vec(),
        }
    }
    /// id of a record
    pub fn id(&self) -> &[u8] {
        &self.id
    }
}

impl ReadResult {
    /// new read result
    pub fn new(id: Vec<u8>, data: Vec<u8>) -> Self {
        Self { id, data }
    }

    /// id of read result
    pub fn id(&self) -> &[u8] {
        &self.id
    }

    /// data from record
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl WriteRequest {
    /// create a new write request
    pub(in crate) fn transaction(id: &TransactionId, stx: &SealedTransaction) -> Self {
        Self {
            id: id.as_ref().to_vec(),
            data: stx.as_ref().to_vec(),
        }
    }

    /// creates a new request to write
    pub(in crate) fn payload(id: &TransactionId, payload: SealedPayload) -> Self {
        Self {
            id: id.as_ref().to_vec(),
            data: payload.as_ref().to_vec(),
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

/// A record in the vault
#[derive(Clone, Serialize, Deserialize)]
pub struct Record(Transaction);

impl Record {
    /// create a new record
    pub fn new(transaction: Transaction) -> Self {
        Self(transaction)
    }

    /// the transaction for this record
    pub fn transaction(&self) -> &Transaction {
        &self.0
    }

    /// get a typed transaction view
    pub fn typed<T: TypedTransaction>(&self) -> Option<&T>
    where
        Transaction: AsView<T>,
    {
        self.transaction().typed()
    }

    /// get a typed transaction view
    pub fn force_typed<T: TypedTransaction>(&self) -> &T
    where
        Transaction: AsView<T>,
    {
        self.transaction().force_typed()
    }

    /// get transaction's chain identifer
    pub fn chain(&self) -> ChainId {
        self.transaction().untyped().chain
    }

    /// get transaction counter
    pub fn ctr(&self) -> Val {
        self.transaction().untyped().ctr
    }

    /// Get the id if the record's Transaction is of type data or revoke
    pub fn id(&self) -> TransactionId {
        self.transaction().untyped().id
    }

    /// open the payload given a key and the cipher.
    pub fn open_payload<P: BoxProvider>(&self, key: &Key<P>, data: &[u8]) -> crate::Result<Vec<u8>> {
        let id = self.force_typed::<DataTransaction>().id;
        let payload = SealedPayload::from(data.to_vec()).decrypt(key, id.as_ref())?;
        Ok(payload)
    }
}

impl Debug for Record {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_struct("Record")
            .field("transaction", &self.transaction().base64())
            .field("data", &self.typed::<DataTransaction>())
            .field("revocation", &self.typed::<RevocationTransaction>())
            .field("init", &self.typed::<InitTransaction>())
            .finish()
    }
}
