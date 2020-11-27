// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::new_ret_no_self)] // Used for new() fns in InitTransaction, DataTransaction & RevocationTransaction impls
                                   // These fns don't return Self, instead return Transaction struct which let us write this code in a simpler way

use crate::{
    crypto_box::{Decrypt, Encrypt},
    types::{
        utils::{BlobId, ChainId, RecordHint, TransactionId, Val},
        AsView, AsViewMut,
    },
};
use std::{
    convert::{Infallible, TryFrom, TryInto},
    fmt::{self, Debug, Formatter},
    hash::Hash,
};

use serde::{Deserialize, Serialize};

/// generic transaction type enum
#[repr(u64)]
#[derive(Debug, Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq)]
pub enum TransactionType {
    Data = 1,
    Revocation = 2,
    Init = 10,
}

impl TryFrom<Val> for TransactionType {
    type Error = crate::Error;

    fn try_from(v: Val) -> Result<Self, Self::Error> {
        match v.u64() {
            1 => Ok(TransactionType::Data),
            2 => Ok(TransactionType::Revocation),
            10 => Ok(TransactionType::Init),
            _ => Err(crate::Error::ValueError(format!(
                "{:?} is not a valid transaction type",
                v
            ))),
        }
    }
}

impl TransactionType {
    /// convert transaction type into its associated number value.
    pub fn val(&self) -> Val {
        Val::from(*self as u64)
    }
}

/// a generic transaction (untyped)
#[derive(Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct Transaction(Vec<u8>);

impl Debug for Transaction {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let t = self.untyped();
        f.debug_struct("Transaction")
            .field(
                "type",
                &TransactionType::try_from(t.type_id).map_err(|_| fmt::Error {})?,
            )
            .field("id", &t.id)
            .field("ctr", &t.ctr)
            .finish()
    }
}

/// untyped transaction view
#[repr(packed)]
#[derive(Debug)]
pub struct UntypedTransaction {
    /// transaction type
    pub type_id: Val,

    /// unique identifer for this transaction
    pub id: TransactionId,

    /// chain identifer
    pub chain: ChainId,

    /// counter value
    pub ctr: Val,
}

impl UntypedTransaction {
    pub fn r#type(&self) -> crate::Result<TransactionType> {
        self.type_id.try_into()
    }
}

/// a data transaction
#[repr(packed)]
#[derive(Debug)]
pub struct DataTransaction {
    /// transaction type
    #[allow(unused)]
    pub type_id: Val,

    /// unique id for this transaction
    pub id: TransactionId,
    #[allow(unused)]

    /// chain identifer
    pub chain: ChainId,
    #[allow(unused)]

    /// counter value
    pub ctr: Val,

    /// the blob identifier for the data referred to by this transaction
    pub blob: BlobId,

    /// a record hint
    pub record_hint: RecordHint,
}

/// a typed transaction
pub trait TypedTransaction {
    fn type_id() -> Val;
}

/// a revocation transaction
#[repr(packed)]
#[derive(Debug)]
pub struct RevocationTransaction {
    /// transaction type
    #[allow(unused)]
    pub type_id: Val,

    /// unique identifer for this transaction
    pub id: TransactionId,

    /// chain identifer
    pub chain: ChainId,

    /// counter
    #[allow(unused)]
    pub ctr: Val,
}

/// transaction that initializes a new chain
#[repr(packed)]
#[derive(Debug)]
pub struct InitTransaction {
    /// transaction type
    #[allow(unused)]
    pub type_id: Val,

    /// unique identifer for this transaction
    pub id: TransactionId,

    /// chain identifer
    pub chain: ChainId,

    /// counter value
    pub ctr: Val,
}

impl DataTransaction {
    /// create a new data transaction.
    pub fn new(chain: ChainId, ctr: Val, id: TransactionId, blob: BlobId, record_hint: RecordHint) -> Transaction {
        let mut transaction = Transaction::default();
        let view: &mut Self = transaction.view_mut();

        view.type_id = (TransactionType::Data as u64).into();
        view.chain = chain;
        view.ctr = ctr;
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
    pub fn new(chain: ChainId, ctr: Val, id: TransactionId) -> Transaction {
        let mut transaction = Transaction::default();
        let view: &mut Self = transaction.view_mut();

        view.type_id = (TransactionType::Revocation as u64).into();
        view.chain = chain;
        view.ctr = ctr;
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

impl InitTransaction {
    /// create a new init transaction.
    pub fn new(chain: ChainId, id: TransactionId, ctr: Val) -> Transaction {
        let mut transaction = Transaction::default();
        let view: &mut Self = transaction.view_mut();

        view.type_id = (TransactionType::Init as u64).into();
        view.id = id;
        view.chain = chain;
        view.ctr = ctr;
        transaction
    }
}

impl TypedTransaction for InitTransaction {
    fn type_id() -> Val {
        TransactionType::Init.val()
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

/// implemented traits.
impl AsView<UntypedTransaction> for Transaction {}
impl AsView<DataTransaction> for Transaction {}
impl AsViewMut<DataTransaction> for Transaction {}
impl AsView<RevocationTransaction> for Transaction {}
impl AsViewMut<RevocationTransaction> for Transaction {}
impl AsView<InitTransaction> for Transaction {}
impl AsViewMut<InitTransaction> for Transaction {}

/// a sealed transaction
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
impl Decrypt<(), Transaction> for SealedTransaction {}

/// a sealed blob
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

impl Decrypt<Infallible, Vec<u8>> for SealedBlob {}
impl Encrypt<SealedBlob> for Vec<u8> {}
impl Encrypt<SealedBlob> for &[u8] {}
