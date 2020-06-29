use crate::{
    crypt_box::{Decrypt, Encrypt},
    types::{
        utils::{Id, IndexHint, Val},
        AsView, AsViewMut,
    },
};
use std::{
    convert::{Infallible, TryFrom},
    fmt::Debug,
    hash::Hash,
};

// generic commit type
#[repr(u64)]
#[derive(Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq)]
enum CommitType {
    DataCommit = 1,
    RevocationCommit = 2,
    InitCommit = 10,
}

// a sealed commit
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct SealedCommit(Vec<u8>);

// a generic commit (untyped)
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Commit(Vec<u8>);

// untyped commit view
#[repr(packed)]
#[derive(Debug)]
pub struct UntypedCommit {
    // commit type
    pub type_id: Val,
    // owner
    pub owner: Id,
    // counter
    pub ctr: Val,
}

// a data commit
#[repr(packed)]
#[derive(Debug)]
pub struct DataCommit {
    // commit type
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
    // hint for indexing
    pub index_hint: IndexHint,
}

// a typed commit
pub trait TypedCommit {
    fn type_id() -> Val;
}

// a revocation commit
#[repr(packed)]
#[derive(Debug)]
pub struct RevocationCommit {
    // commit type
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

// commit that initializes the chain
#[repr(packed)]
#[derive(Debug)]
pub struct InitCommit {
    // commit type
    #[allow(unused)]
    pub type_id: Val,
    // owner
    #[allow(unused)]
    pub owner: Id,
    // counter
    pub ctr: Val,
}

// some sealed data
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct SealedPayload(Vec<u8>);

impl CommitType {
    // convert commit type into the number
    pub fn val(&self) -> Val {
        Val::from(*self as u64)
    }
}

impl DataCommit {
    pub fn new(owner: Id, ctr: Val, id: Id, index_hint: IndexHint) -> Commit {
        let mut commit = Commit::default();
        let view: &mut Self = commit.view_mut();

        view.type_id = (CommitType::DataCommit as u64).into();
        view.owner = owner;
        view.ctr = ctr;
        view.id = id;
        view.index_hint = index_hint;
        commit
    }
}

impl TypedCommit for DataCommit {
    fn type_id() -> Val {
        CommitType::DataCommit.val()
    }
}

impl RevocationCommit {
    pub fn new(owner: Id, ctr: Val, id: Id) -> Commit {
        let mut commit = Commit::default();
        let view: &mut Self = commit.view_mut();

        view.type_id = (CommitType::RevocationCommit as u64).into();
        view.owner = owner;
        view.ctr = ctr;
        view.id = id;
        commit
    }
}
impl TypedCommit for RevocationCommit {
    fn type_id() -> Val {
        CommitType::RevocationCommit.val()
    }
}

impl Commit {
    pub fn untyped(&self) -> &UntypedCommit {
        self.view()
    }

    pub fn typed<T: TypedCommit>(&self) -> Option<&T>
    where
        Self: AsView<T>,
    {
        match self.untyped().type_id {
            type_id if type_id == T::type_id() => Some(self.view()),
            _ => None,
        }
    }

    pub fn typed_mut<T: TypedCommit>(&mut self) -> Option<&mut T>
    where
        Self: AsViewMut<T>,
    {
        match self.untyped().type_id {
            type_id if type_id == T::type_id() => Some(self.view_mut()),
            _ => None,
        }
    }

    pub fn force_typed<T: TypedCommit>(&self) -> &T
    where
        Self: AsView<T>,
    {
        self.typed().expect("This commit cannot be viewed as `T`")
    }

    pub fn force_typed_mut<T: TypedCommit>(&mut self) -> &mut T
    where
        Self: AsViewMut<T>,
    {
        self.typed_mut()
            .expect("This commit cannot be viewed as `T`")
    }
}

impl InitCommit {
    pub fn new(owner: Id, ctr: Val) -> Commit {
        let mut commit = Commit::default();
        let view: &mut Self = commit.view_mut();

        view.type_id = (CommitType::InitCommit as u64).into();
        view.owner = owner;
        view.ctr = ctr;
        commit
    }
}

impl TypedCommit for InitCommit {
    fn type_id() -> Val {
        CommitType::InitCommit.val()
    }
}

impl From<Vec<u8>> for SealedCommit {
    fn from(vec: Vec<u8>) -> Self {
        Self(vec)
    }
}
impl AsRef<[u8]> for SealedCommit {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl AsMut<[u8]> for SealedCommit {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}
impl Decrypt<(), Commit> for SealedCommit {}

impl Default for Commit {
    fn default() -> Self {
        Self(vec![0; 88])
    }
}
impl TryFrom<Vec<u8>> for Commit {
    type Error = ();
    fn try_from(vec: Vec<u8>) -> Result<Self, Self::Error> {
        match vec.len() {
            88 => Ok(Self(vec)),
            _ => Err(()),
        }
    }
}
impl AsRef<[u8]> for Commit {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl AsMut<[u8]> for Commit {
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

impl Encrypt<SealedCommit> for Commit {}
impl AsView<UntypedCommit> for Commit {}
impl AsView<DataCommit> for Commit {}
impl AsViewMut<DataCommit> for Commit {}
impl AsView<RevocationCommit> for Commit {}
impl AsViewMut<RevocationCommit> for Commit {}
impl AsView<InitCommit> for Commit {}
impl AsViewMut<InitCommit> for Commit {}
impl Decrypt<Infallible, Vec<u8>> for SealedPayload {}
impl Encrypt<SealedPayload> for Vec<u8> {}
