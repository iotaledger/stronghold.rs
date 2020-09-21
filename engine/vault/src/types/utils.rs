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

use crate::{base64::Base64Encodable, crypto_box::BoxProvider};
use std::{
    cmp::Ordering,
    fmt::{self, Debug, Formatter},
    hash::Hash,
    ops::{Add, AddAssign},
    convert::{TryFrom, TryInto},
};

use serde::{Deserialize, Serialize};

/// a record hint
#[repr(transparent)]
#[derive(Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecordHint([u8; 24]);

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

/// a big endian encoded number
#[repr(transparent)]
#[derive(Copy, Clone, Hash, Eq, PartialEq)]
pub struct Val([u8; 8]);

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

/// A chain identifier
#[repr(transparent)]
#[derive(Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChainId([u8; 24]);

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


/// A transaction identifier
#[repr(transparent)]
#[derive(Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransactionId([u8; 24]);

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

/// A blob identifier
#[repr(transparent)]
#[derive(Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlobId([u8; 24]);

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
