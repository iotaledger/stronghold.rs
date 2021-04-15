// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{base64::Base64Encodable, crypto_box::BoxProvider};
use std::{
    cmp::Ordering,
    convert::{TryFrom, TryInto},
    fmt::{self, Debug, Display, Formatter},
    hash::Hash,
    ops::{Add, AddAssign},
};

use serde::{Deserialize, Serialize};

/// a record hint.  Used as a hint to what this data is.
#[repr(transparent)]
#[derive(Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecordHint([u8; 24]);

/// A record identifier.  Contains a ChainID which refers to the "chain" of transactions in the Version.
#[repr(transparent)]
#[derive(Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecordId(pub(crate) ChainId);

/// Client Id type used to identify a client.
#[repr(transparent)]
#[derive(Copy, Clone, Default, Hash, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClientId(pub Id);

/// Vault Id type used to identify a vault.
#[repr(transparent)]
#[derive(Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub struct VaultId(pub Id);

/// A chain identifier.  Used to identify a set of transactions in a version.
#[repr(transparent)]
#[derive(Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChainId([u8; 24]);

/// A generic Id type used as the underlying type for the `ClientId` and `VaultId` types.
#[repr(transparent)]
#[derive(Copy, Clone, Hash, Default, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub struct Id([u8; 24]);

/// A transaction identifier
#[repr(transparent)]
#[derive(Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransactionId([u8; 24]);

/// A blob identifier
#[repr(transparent)]
#[derive(Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlobId([u8; 24]);

/// a big endian encoded number
#[repr(transparent)]
#[derive(Copy, Clone, Hash, Eq, PartialEq)]
pub struct Val([u8; 8]);

impl RecordHint {
    /// create a new random Id for hint
    pub fn new(hint: impl AsRef<[u8]>) -> crate::Result<Self> {
        let hint = match hint.as_ref() {
            hint if hint.len() <= 24 => hint,
            _ => return Err(crate::Error::InterfaceError),
        };

        // copy hint
        let mut buf = [0; 24];
        buf[..hint.len()].copy_from_slice(hint);
        Ok(Self(buf))
    }
}

impl AsRef<[u8]> for RecordHint {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl Debug for RecordHint {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.0.base64())
    }
}

impl From<[u8; 24]> for RecordHint {
    fn from(bs: [u8; 24]) -> Self {
        Self(bs)
    }
}

impl Val {
    pub fn u64(self) -> u64 {
        u64::from_be_bytes(self.0)
    }
}

impl From<u64> for Val {
    fn from(num: u64) -> Self {
        Self(num.to_be_bytes())
    }
}

impl PartialOrd for Val {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.u64().partial_cmp(&other.u64())
    }
}

impl Ord for Val {
    fn cmp(&self, other: &Self) -> Ordering {
        self.u64().cmp(&other.u64())
    }
}

impl Add<u64> for Val {
    type Output = Self;
    fn add(self, rhs: u64) -> Self::Output {
        Self::from(self.u64() + rhs)
    }
}

impl AddAssign<u64> for Val {
    fn add_assign(&mut self, rhs: u64) {
        *self = *self + rhs;
    }
}

impl Debug for Val {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.u64())
    }
}

impl AsRef<[u8]> for ChainId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Debug for ChainId {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Chain({})", self.0.base64())
    }
}

impl ChainId {
    pub fn random<P: BoxProvider>() -> crate::Result<Self> {
        let mut buf = [0; 24];
        P::random_buf(&mut buf)?;

        Ok(Self(buf))
    }

    pub fn load(data: &[u8]) -> crate::Result<Self> {
        data.try_into()
    }
}

impl TryFrom<&[u8]> for ChainId {
    type Error = crate::Error;

    fn try_from(bs: &[u8]) -> Result<Self, Self::Error> {
        if bs.len() != 24 {
            return Err(crate::Error::InterfaceError);
        }

        let mut tmp = [0; 24];
        tmp.copy_from_slice(bs);
        Ok(Self(tmp))
    }
}

impl TryFrom<Vec<u8>> for ChainId {
    type Error = crate::Error;

    fn try_from(bs: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bs.as_slice())
    }
}

impl AsRef<[u8]> for TransactionId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Debug for TransactionId {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Transaction({})", self.0.base64())
    }
}

impl From<&TransactionId> for Vec<u8> {
    fn from(id: &TransactionId) -> Self {
        id.0.to_vec()
    }
}

impl TransactionId {
    pub fn random<P: BoxProvider>() -> crate::Result<Self> {
        let mut buf = [0; 24];
        P::random_buf(&mut buf)?;

        Ok(Self(buf))
    }

    pub fn load(data: &[u8]) -> crate::Result<Self> {
        data.try_into()
    }
}

impl TryFrom<&[u8]> for TransactionId {
    type Error = crate::Error;

    fn try_from(bs: &[u8]) -> Result<Self, Self::Error> {
        if bs.len() != 24 {
            return Err(crate::Error::InterfaceError);
        }

        let mut tmp = [0; 24];
        tmp.copy_from_slice(bs);
        Ok(Self(tmp))
    }
}

impl AsRef<[u8]> for BlobId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<BlobId> for Vec<u8> {
    fn from(id: BlobId) -> Self {
        id.0.to_vec()
    }
}

impl From<&BlobId> for Vec<u8> {
    fn from(id: &BlobId) -> Self {
        id.0.to_vec()
    }
}

impl Debug for BlobId {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Blob({})", self.0.base64())
    }
}

impl TryFrom<&[u8]> for BlobId {
    type Error = crate::Error;

    fn try_from(bs: &[u8]) -> Result<Self, Self::Error> {
        if bs.len() != 24 {
            return Err(crate::Error::InterfaceError);
        }

        let mut tmp = [0; 24];
        tmp.copy_from_slice(bs);
        Ok(Self(tmp))
    }
}

impl BlobId {
    pub fn random<P: BoxProvider>() -> crate::Result<Self> {
        let mut buf = [0; 24];
        P::random_buf(&mut buf)?;
        Ok(Self(buf))
    }
}

impl Debug for RecordId {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Record({})", self.0.as_ref().base64())
    }
}

impl Display for RecordId {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.0.as_ref().base64())
    }
}

impl TryFrom<Vec<u8>> for RecordId {
    type Error = crate::Error;

    fn try_from(bs: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(RecordId(bs.try_into()?))
    }
}

impl TryFrom<&[u8]> for RecordId {
    type Error = crate::Error;

    fn try_from(bs: &[u8]) -> Result<Self, Self::Error> {
        Ok(RecordId(bs.try_into()?))
    }
}

impl RecordId {
    pub fn random<P: BoxProvider>() -> crate::Result<Self> {
        Ok(RecordId(ChainId::random::<P>()?))
    }

    /// load record_id from data
    pub fn load(data: &[u8]) -> crate::Result<Self> {
        Ok(RecordId(ChainId::load(data)?))
    }
}

impl AsRef<[u8]> for Id {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Debug for Id {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Chain({})", self.0.base64())
    }
}

impl Id {
    /// Create a new random `Id`.
    pub fn random<P: BoxProvider>() -> crate::Result<Self> {
        let mut buf = [0; 24];
        P::random_buf(&mut buf)?;

        Ok(Self(buf))
    }

    /// Load an `Id` from some data.
    pub fn load(data: &[u8]) -> crate::Result<Self> {
        data.try_into()
    }
}

impl VaultId {
    /// Create a new random `VaultId`.
    pub fn random<P: BoxProvider>() -> crate::Result<Self> {
        Ok(VaultId(Id::random::<P>()?))
    }

    /// Load a `VaultId` from some data.
    pub fn load(data: &[u8]) -> crate::Result<Self> {
        Ok(VaultId(Id::load(data)?))
    }
}

impl ClientId {
    /// Create a new random `ClientId`.
    pub fn random<P: BoxProvider>() -> crate::Result<Self> {
        Ok(ClientId(Id::random::<P>()?))
    }

    /// Load a `ClientId` from some data.
    pub fn load(data: &[u8]) -> crate::Result<Self> {
        Ok(ClientId(Id::load(data)?))
    }
}

impl TryFrom<&[u8]> for Id {
    type Error = crate::Error;

    fn try_from(bs: &[u8]) -> Result<Self, Self::Error> {
        if bs.len() != 24 {
            return Err(crate::Error::OtherError("Id error".into()));
        }

        let mut tmp = [0; 24];
        tmp.copy_from_slice(bs);
        Ok(Self(tmp))
    }
}

impl TryFrom<Vec<u8>> for Id {
    type Error = crate::Error;

    fn try_from(bs: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bs.as_slice())
    }
}

impl TryFrom<Vec<u8>> for ClientId {
    type Error = crate::Error;

    fn try_from(bs: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(ClientId(bs.try_into()?))
    }
}

impl TryFrom<&[u8]> for ClientId {
    type Error = crate::Error;

    fn try_from(bs: &[u8]) -> Result<Self, Self::Error> {
        Ok(ClientId(bs.try_into()?))
    }
}

impl Debug for ClientId {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "ClientId({})", self.0.as_ref().base64())
    }
}

impl TryFrom<Vec<u8>> for VaultId {
    type Error = crate::Error;

    fn try_from(bs: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(VaultId(bs.try_into()?))
    }
}

impl TryFrom<&[u8]> for VaultId {
    type Error = crate::Error;

    fn try_from(bs: &[u8]) -> Result<Self, Self::Error> {
        Ok(VaultId(bs.try_into()?))
    }
}

impl Debug for VaultId {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "VaultId({})", self.0.as_ref().base64())
    }
}

impl Into<Vec<u8>> for VaultId {
    fn into(self) -> Vec<u8> {
        self.0 .0.to_vec()
    }
}

impl AsRef<[u8]> for VaultId {
    fn as_ref(&self) -> &[u8] {
        &self.0 .0
    }
}

impl Into<Vec<u8>> for ClientId {
    fn into(self) -> Vec<u8> {
        self.0 .0.to_vec()
    }
}

impl AsRef<[u8]> for ClientId {
    fn as_ref(&self) -> &[u8] {
        &self.0 .0
    }
}

impl Into<String> for ClientId {
    fn into(self) -> String {
        self.0.as_ref().base64()
    }
}

impl Into<String> for VaultId {
    fn into(self) -> String {
        self.0.as_ref().base64()
    }
}
