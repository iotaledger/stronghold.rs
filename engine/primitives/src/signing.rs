// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

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
