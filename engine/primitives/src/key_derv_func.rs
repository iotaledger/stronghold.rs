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

/// A key derivation function info block
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct KeyDervFuncInfo {
    /// The key derive function id
    pub id: &'static str,
    /// A range of the supported output lengths
    pub output_lens: Range<usize>,
    /// A range of the supported key lengths
    pub key_lens: Range<usize>,
    /// A range of the supported salt lengths
    pub salt_lens: Range<usize>,
    /// A range of the supported info lengths
    pub info_lens: Range<usize>,
}

/// A key derivation function interface
pub trait KeyDervFunc {
    /// returns the information block about the key derivation function
    fn info(&self) -> KeyDervFuncInfo;
    /// derive bytes from the base key with salt and info. Outputs to the buffer `buf`.
    fn derive(&self, buf: &mut [u8], base_key: &[u8], salt: &[u8], info: &[u8])
        -> Result<(), Box<dyn Error + 'static>>;
}
