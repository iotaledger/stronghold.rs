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

#[repr(u64)]
#[derive(Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq)]
enum CommitType {
    DataCommit = 1,
    RevocationCommit = 2,
    InitCommit = 10,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct SealedCommit(Vec<u8>);

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Commit(Vec<u8>);

#[repr(packed)]
#[derive(Debug)]
pub struct UntypedCommit {
    pub r#type: Val,
    pub owner: Id,
    pub ctr: Val,
}

#[repr(packed)]
#[derive(Debug)]
pub struct DataCommit {
    #[allow(unused)]
    pub r#type: Val,
    #[allow(unused)]
    pub owner: Id,
    #[allow(unused)]
    pub ctr: Val,
    pub uid: Id,
    pub index_hint: IndexHint,
}

pub trait TypedCommit {
    fn r#type() -> Val;
}

#[repr(packed)]
#[derive(Debug)]
pub struct RevocationCommit {
    #[allow(unused)]
    pub r#type: Val,
    #[allow(unused)]
    pub owner: Id,
    #[allow(unused)]
    pub ctr: Val,
    pub uid: Id,
}

#[repr(packed)]
#[derive(Debug)]
pub struct InitCommit {
    #[allow(unused)]
    pub r#type: Val,
    #[allow(unused)]
    pub owner: Id,
    pub ctr: Val,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct SealedPayload(Vec<u8>);

impl CommitType {
    pub fn val(&self) -> Val {
        Val::from(*self as u64)
    }
}

impl DataCommit {
    pub fn new(owner: Id, ctr: Val, uid: Id, index_hint: IndexHint) -> Commit {
        let mut commit = Commit::default();
        let view: &mut Self = commit.view_mut();

        view.r#type = (CommitType::DataCommit as u64).into();
        view.owner = owner;
        view.ctr = ctr;
        view.uid = uid;
        view.index_hint = index_hint;
        commit
    }
}

impl TypedCommit for DataCommit {
    fn r#type() -> Val {
        CommitType::DataCommit.val()
    }
}

impl RevocationCommit {
    pub fn new(owner: Id, ctr: Val, uid: Id) -> Commit {
        let mut commit = Commit::default();
        let view: &mut Self = commit.view_mut();

        view.r#type = (CommitType::RevocationCommit as u64).into();
        view.owner = owner;
        view.ctr = ctr;
        view.uid = uid;
        commit
    }
}
impl TypedCommit for RevocationCommit {
    fn r#type() -> Val {
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
        match self.untyped().r#type {
            r#type if r#type == T::r#type() => Some(self.view()),
            _ => None,
        }
    }

    pub fn typed_mut<T: TypedCommit>(&mut self) -> Option<&mut T>
    where
        Self: AsViewMut<T>,
    {
        match self.untyped().r#type {
            r#type if r#type == T::r#type() => Some(self.view_mut()),
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

        view.r#type = (CommitType::InitCommit as u64).into();
        view.owner = owner;
        view.ctr = ctr;
        commit
    }
}

impl TypedCommit for InitCommit {
    fn r#type() -> Val {
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
