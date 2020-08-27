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

use crate::rng::{PublicKeyGen, SecretKeyGen};
use std::{error::Error, ops::Range};

/// Signature information block
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct SignInfo {
    /// the signature ID
    pub id: &'static str,
    /// Range of supported signature lengths
    pub sig_lens: Range<usize>,
    /// Range of supported secret/private key lengths
    pub secret_key_lens: Range<usize>,
    /// Range of supported public key lengths.
    pub public_key_lens: Range<usize>,
}

pub trait Sign: SecretKeyGen + PublicKeyGen {
    /// returns info about the signer
    fn info(&self) -> SignInfo;
    /// signs data in the buffer using the secret key and returns the signature length.
    fn sign(&self, buf: &mut [u8], data: &[u8], secret_key: &[u8]) -> Result<usize, Box<dyn Error + 'static>>;
    /// verify the signature for the data with the public key.  Returns an error if the signature was invalid.
    fn verify(&self, data: &[u8], sig: &[u8], public_key: &[u8]) -> Result<(), Box<dyn Error + 'static>>;
}
