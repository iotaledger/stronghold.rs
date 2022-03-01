// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::new_ret_no_self)] // Used for new() fns in InitTransaction, DataTransaction & RevocationTransaction impls
                                   // These fns don't return Self, instead return Transaction struct which let us write this code in a simpler way

use crate::vault::{
    crypto_box::{Decrypt, Encrypt},
    types::{
        utils::{BlobId, ChainId, RecordHint, Val},
        AsView, AsViewMut,
    },
};

use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Debug, Formatter},
    hash::Hash,
};

/// A generic transaction type enum.  Data Transactions refer to `SealedBlobs` while revocation transactions are used to
/// revoke records.
#[repr(u64)]
#[derive(Debug, Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq)]
pub enum TransactionType {
    Data = 1,
    Revocation = 2,
}

impl TransactionType {
    /// convert transaction type into its associated number value.
    pub fn val(&self) -> Val {
        Val::from(*self as u64)
    }
}

/// a generic transaction (untyped) in a byte format.
#[derive(Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct Transaction(Vec<u8>);

impl Debug for Transaction {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_struct("Transaction")
            .field("type", &self)
            .field("id", &self.untyped().id)
            .finish()
    }
}

/// untyped transaction view
#[repr(packed)]
#[derive(Debug)]
pub struct UntypedTransaction {
    /// transaction type
    pub type_id: Val,

    /// id identifer
    pub id: ChainId,
}

/// A structured data transaction
#[repr(packed)]
#[derive(Debug)]
pub struct DataTransaction {
    /// transaction type
    #[allow(unused)]
    pub type_id: Val,

    /// Length of the unencrypted blob data
    pub len: Val,

    /// id identifer
    pub id: ChainId,
    #[allow(unused)]

    /// the blob identifier for the data referred to by this transaction
    pub blob: BlobId,

    /// a record hint
    pub record_hint: RecordHint,
}

/// a typed transaction
pub trait TypedTransaction {
    fn type_id() -> Val;
}

/// A structured revocation transaction.
#[repr(packed)]
#[derive(Debug)]
pub struct RevocationTransaction {
    /// transaction type
    #[allow(unused)]
    pub type_id: Val,

    /// id identifer
    pub id: ChainId,
}

impl DataTransaction {
    /// create a new data transaction from a [`ChainId`], a len, a [`BlobId`] and a [`RecordHint`].
    pub fn new(id: ChainId, len: u64, blob: BlobId, record_hint: RecordHint) -> Transaction {
        let mut transaction = Transaction::default();
        let view: &mut Self = transaction.view_mut();

        view.type_id = (TransactionType::Data as u64).into();
        view.len = len.into();
        view.id = id;
        view.blob = blob;
        view.record_hint = record_hint;
        transaction
    }
}

impl TypedTransaction for DataTransaction {
    fn type_id() -> Val {
        TransactionType::Data.val()
    }
}

impl RevocationTransaction {
    /// create a new revocation transaction.
    pub fn new(id: ChainId) -> Transaction {
        let mut transaction = Transaction::default();
        let view: &mut Self = transaction.view_mut();

        view.type_id = (TransactionType::Revocation as u64).into();
        view.id = id;
        transaction
    }
}
impl TypedTransaction for RevocationTransaction {
    fn type_id() -> Val {
        TransactionType::Revocation.val()
    }
}

impl Transaction {
    pub fn untyped(&self) -> &UntypedTransaction {
        self.view()
    }

    pub fn typed<T: TypedTransaction>(&self) -> Option<&T>
    where
        Self: AsView<T>,
    {
        match self.untyped().type_id {
            type_id if type_id == T::type_id() => Some(self.view()),
            _ => None,
        }
    }
}

const TRANSACTION_MAX_BYTES: usize = 112;

impl Default for Transaction {
    fn default() -> Self {
        Self(vec![0; TRANSACTION_MAX_BYTES])
    }
}
impl TryFrom<Vec<u8>> for Transaction {
    type Error = ();
    fn try_from(vec: Vec<u8>) -> Result<Self, Self::Error> {
        match vec.len() {
            TRANSACTION_MAX_BYTES => Ok(Self(vec)),
            _ => Err(()),
        }
    }
}
impl AsRef<[u8]> for Transaction {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl AsMut<[u8]> for Transaction {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

/// implemented traits for the transaction types.  Allows the transaction types to be turned into views and converted
/// into bytes.
impl AsView<UntypedTransaction> for Transaction {}
impl AsView<DataTransaction> for Transaction {}
impl AsViewMut<DataTransaction> for Transaction {}
impl AsView<RevocationTransaction> for Transaction {}
impl AsViewMut<RevocationTransaction> for Transaction {}

/// a sealed transaction
#[derive(Deserialize, Serialize, Clone)]
pub struct SealedTransaction(Vec<u8>);

impl From<Vec<u8>> for SealedTransaction {
    fn from(vec: Vec<u8>) -> Self {
        Self(vec)
    }
}

impl From<&[u8]> for SealedTransaction {
    fn from(bs: &[u8]) -> Self {
        Self(bs.to_vec())
    }
}

impl AsRef<[u8]> for SealedTransaction {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for SealedTransaction {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Encrypt<SealedTransaction> for Transaction {}
impl Decrypt<Transaction> for SealedTransaction {}

/// A sealed blob type which contains encrypted data in byte format.
#[derive(Deserialize, Serialize, Clone)]
pub struct SealedBlob(Vec<u8>);

impl From<Vec<u8>> for SealedBlob {
    fn from(vec: Vec<u8>) -> Self {
        Self(vec)
    }
}

impl From<&[u8]> for SealedBlob {
    fn from(bs: &[u8]) -> Self {
        Self(bs.to_vec())
    }
}

impl AsRef<[u8]> for SealedBlob {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for SealedBlob {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

/// Encryption and Decryption Traits for the [`SealedBlob`], [`Vec<u8>`], and [`&[u8]`] types.
impl Decrypt<Vec<u8>> for SealedBlob {}
impl Encrypt<SealedBlob> for Vec<u8> {}
impl Encrypt<SealedBlob> for &[u8] {}
