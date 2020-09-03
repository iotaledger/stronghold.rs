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
};

use serde::{Deserialize, Serialize};

/// An Id with length of 24
#[repr(transparent)]
#[derive(Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub struct Id([u8; 24]);

/// a record hint
#[repr(transparent)]
#[derive(Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecordHint([u8; 24]);

/// a big endian encoded number
#[repr(transparent)]
#[derive(Copy, Clone, Hash, Eq, PartialEq)]
pub struct Val([u8; 8]);

impl Id {
    /// create a random ID
    pub fn random<P: BoxProvider>() -> crate::Result<Self> {
        let mut buf = [0; 24];
        P::random_buf(&mut buf)?;

        Ok(Self(buf))
    }

    /// load an ID from inputted `data`
    pub fn load(data: &[u8]) -> crate::Result<Self> {
        let mut id = match data.len() {
            len if len == 24 => [0; 24],
            _ => return Err(crate::Error::InterfaceError),
        };
        id.copy_from_slice(data);
        Ok(Self(id))
    }
}

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

impl Val {
    /// the val as u64
    pub fn u64(self) -> u64 {
        u64::from_be_bytes(self.0)
    }
    /// returns current val and increments it by one after
    pub fn postfix_increment(&mut self) -> Self {
        let old = *self;
        *self += 1;
        old
    }
}

impl AsRef<[u8]> for Id {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl Debug for Id {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.0.base64())
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
