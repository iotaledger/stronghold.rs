use crate::{
    crypto_box::{Decrypt, Encrypt},
    types::{
        utils::{Id, RecordHint, Val},
        AsView, AsViewMut,
    },
};
use std::{
    convert::{Infallible, TryFrom},
    fmt::Debug,
    hash::Hash,
};

use serde::{Deserialize, Serialize};

// generic transaction type
#[repr(u64)]
#[derive(Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq)]
enum TransactionType {
    DataTransaction = 1,
    RevocationTransaction = 2,
    InitTransaction = 10,
}

// a sealed transaction
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct SealedTransaction(Vec<u8>);

// a generic transaction (untyped)
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct Transaction(Vec<u8>);

// untyped transaction view
#[repr(packed)]
#[derive(Debug)]
pub struct UntypedTransaction {
    // transaction type
    pub type_id: Val,
    // owner
    pub owner: Id,
    // counter
    pub ctr: Val,
}

// a data transaction
#[repr(packed)]
#[derive(Debug)]
pub struct DataTransaction {
    // transaction type
    #[allow(unused)]
    pub type_id: Val,
    #[allow(unused)]
    // owner
    pub owner: Id,
    #[allow(unused)]
    // counter
    pub ctr: Val,
    // id for this entry
    pub id: Id,
    // a record hint
    pub record_hint: RecordHint,
}

// a typed transaction
pub trait TypedTransaction {
    fn type_id() -> Val;
}

// a revocation transaction
#[repr(packed)]
#[derive(Debug)]
pub struct RevocationTransaction {
    // transaction type
    #[allow(unused)]
    pub type_id: Val,
    // owner
    #[allow(unused)]
    pub owner: Id,
    // counter
    #[allow(unused)]
    pub ctr: Val,
    // id for entry
    pub id: Id,
}

// transaction that initializes the chain
#[repr(packed)]
#[derive(Debug)]
pub struct InitTransaction {
    // transaction type
    #[allow(unused)]
    pub type_id: Val,
    // owner
    #[allow(unused)]
    pub owner: Id,
    // counter
    pub ctr: Val,
}

// some sealed payload data
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct SealedPayload(Vec<u8>);

impl TransactionType {
    // convert transaction type into the number
    pub fn val(&self) -> Val {
        Val::from(*self as u64)
    }
}

impl DataTransaction {
    // create a new data transaction.
    pub fn new(owner: Id, ctr: Val, id: Id, record_hint: RecordHint) -> Transaction {
        let mut transaction = Transaction::default();
        let view: &mut Self = transaction.view_mut();

        view.type_id = (TransactionType::DataTransaction as u64).into();
        view.owner = owner;
        view.ctr = ctr;
        view.id = id;
        view.record_hint = record_hint;
        transaction
    }
}

impl TypedTransaction for DataTransaction {
    fn type_id() -> Val {
        TransactionType::DataTransaction.val()
    }
}

impl RevocationTransaction {
    // create a new revocation transaction.
    pub fn new(owner: Id, ctr: Val, id: Id) -> Transaction {
        let mut transaction = Transaction::default();
        let view: &mut Self = transaction.view_mut();

        view.type_id = (TransactionType::RevocationTransaction as u64).into();
        view.owner = owner;
        view.ctr = ctr;
        view.id = id;
        transaction
    }
}
impl TypedTransaction for RevocationTransaction {
    fn type_id() -> Val {
        TransactionType::RevocationTransaction.val()
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

    pub fn typed_mut<T: TypedTransaction>(&mut self) -> Option<&mut T>
    where
        Self: AsViewMut<T>,
    {
        match self.untyped().type_id {
            type_id if type_id == T::type_id() => Some(self.view_mut()),
            _ => None,
        }
    }

    pub fn force_typed<T: TypedTransaction>(&self) -> &T
    where
        Self: AsView<T>,
    {
        self.typed()
            .expect("This transaction cannot be viewed as `T`")
    }

    pub fn force_typed_mut<T: TypedTransaction>(&mut self) -> &mut T
    where
        Self: AsViewMut<T>,
    {
        self.typed_mut()
            .expect("This transaction cannot be viewed as `T`")
    }
}

impl InitTransaction {
    // create a new init transaction.
    pub fn new(owner: Id, ctr: Val) -> Transaction {
        let mut transaction = Transaction::default();
        let view: &mut Self = transaction.view_mut();

        view.type_id = (TransactionType::InitTransaction as u64).into();
        view.owner = owner;
        view.ctr = ctr;
        transaction
    }
}

impl TypedTransaction for InitTransaction {
    fn type_id() -> Val {
        TransactionType::InitTransaction.val()
    }
}

impl From<Vec<u8>> for SealedTransaction {
    fn from(vec: Vec<u8>) -> Self {
        Self(vec)
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

impl Default for Transaction {
    fn default() -> Self {
        Self(vec![0; 88])
    }
}
impl TryFrom<Vec<u8>> for Transaction {
    type Error = ();
    fn try_from(vec: Vec<u8>) -> Result<Self, Self::Error> {
        match vec.len() {
            88 => Ok(Self(vec)),
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

impl From<Vec<u8>> for SealedPayload {
    fn from(vec: Vec<u8>) -> Self {
        Self(vec)
    }
}
impl AsRef<[u8]> for SealedPayload {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl AsMut<[u8]> for SealedPayload {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

// implemented traits.
impl Encrypt<SealedTransaction> for Transaction {}
impl Decrypt<(), Transaction> for SealedTransaction {}
impl AsView<UntypedTransaction> for Transaction {}
impl AsView<DataTransaction> for Transaction {}
impl AsViewMut<DataTransaction> for Transaction {}
impl AsView<RevocationTransaction> for Transaction {}
impl AsViewMut<RevocationTransaction> for Transaction {}
impl AsView<InitTransaction> for Transaction {}
impl AsViewMut<InitTransaction> for Transaction {}
impl Decrypt<Infallible, Vec<u8>> for SealedPayload {}
impl Encrypt<SealedPayload> for Vec<u8> {}
