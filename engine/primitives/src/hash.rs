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

use std::{error::Error, ops::Range};

/// An information block describing a Hash.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct HashInfo {
    /// A id of hash
    pub id: &'static str,
    /// The hash's length
    pub hash_len: usize,
    /// A range for supported hash lengths
    pub hash_lens: Range<usize>,
}

/// A Hash interface
pub trait Hash {
    /// Get the information block that describes the hash
    fn info(&self) -> HashInfo;
    /// hashes data and returns the hash length. `buf` contains the outgoing hashed data.  
    fn hash(&self, buf: &mut [u8], data: &[u8]) -> Result<usize, Box<dyn Error + 'static>>;
}

/// a variable length hash
pub trait VarLenHash: Hash {
    /// hashes the data and returns the hash length. `buf` contains the outgoing hashed data.
    fn var_len_hash(&self, buf: &mut [u8], data: &[u8]) -> Result<usize, Box<dyn Error + 'static>>;
}
