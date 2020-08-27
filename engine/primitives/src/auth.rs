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

use crate::rng::SecretKeyGen;

use std::{error::Error, ops::Range};

/// Message Authentication Code information block
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct MessageAuthCodeInfo {
    /// the ID for the MAC
    pub id: &'static str,
    /// indicates whether or not the MAC a one shot
    pub one_time: bool,
    /// length of the MAC
    pub len: usize,
    /// A range of the supported MAC lengths
    pub mac_lens: Range<usize>,
    /// A range of the supported key lengths
    pub key_lens: Range<usize>,
}

/// a Message authentication interface (MAC) that is stateless and can be a one shot.
pub trait MessageAuthCode: SecretKeyGen {
    /// get the info about the MAC
    fn info(&self) -> MessageAuthCodeInfo;
    /// authenticate the `data` using the `key` through the `buf` buffer.  Returns the MAC length in a `Result`
    fn auth(&self, buf: &mut [u8], data: &[u8], key: &[u8]) -> Result<usize, Box<dyn Error + 'static>>;
}

/// an extension for a Variable length Message Authentication Code (MAC).
pub trait VarLenMessageAuthCode: MessageAuthCode {
    /// Authenticates the `data` using a `key` through the `buf` buffer.  Returns the MAC's length in a `Result`.
    fn varlen_auth(&self, buf: &mut [u8], data: &[u8], key: &[u8]) -> Result<usize, Box<dyn Error + 'static>>;
}
