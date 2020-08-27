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

use crate::rng::SecretKeyGen;

/// A block of information about the implemented Cipher
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct CipherInfo {
    /// The cipher id
    pub id: &'static str,
    /// Indicates whether or not the cipher is one time.
    pub one_time: bool,
    /// A range of supported key lengths
    pub key_lens: Range<usize>,
    /// A range of supported nonce lengths
    pub nonce_lens: Range<usize>,
    /// A range of supported AEAD tag lengths. Without AEAD this field defaults to `0..0`
    pub tag_lens: Range<usize>,
}

/// A one shot stateless cipher.  Implements the `SecretKeyGen` trait.
pub trait Cipher: SecretKeyGen {
    /// returns cipher info block
    fn info(&self) -> CipherInfo;
    /// predicts the max encrypted cipher length given a `plaintext_len` (in bytes)
    fn predict_encrypted_max(&self, plain_len: usize) -> usize;
    /// encrypts the plaintext in-place and returns the cipher's length. `buf` contains the incoming plaintext buffer.
    fn encrypt(
        &self,
        buf: &mut [u8],
        plain_len: usize,
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>>;

    /// encrypts the plaintext and returns the plaintext's length. `buf` contains the incoming plaintext buffer.
    fn encrypt_to(
        &self,
        buf: &mut [u8],
        plain: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>>;

    /// decrypts the cipher's bytes in-place and returns the plaintext length. `buf` contains the outgoing plaintext
    /// buffer
    fn decrypt(
        &self,
        buf: &mut [u8],
        cipher_len: usize,
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>>;

    /// decrypts the ciphertext and returns the plaintext's length. `buf` contains the outgoing plaintext
    /// buffer
    fn decrypt_to(
        &self,
        buf: &mut [u8],
        cipher: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>>;
}

/// an AEAD Extension for the Cipher
pub trait AeadCipher: Cipher {
    /// Seals the Plaintext bytes in place with AEAD and returns the Cipher length. `buf` contains the incoming
    /// plaintext buffer
    fn seal(
        &self,
        buf: &mut [u8],
        plain_len: usize,
        ad: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>>;

    /// Seals the plaintext and returns the Cipher's length using AEAD. `buf` contains the incoming plaintext
    /// buffer
    fn seal_with(
        &self,
        buf: &mut [u8],
        plain: &[u8],
        ad: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>>;

    /// Opens the Ciphertext length in-place and returns the plaintext length using AEAD. `buf` contains the outgoing
    /// plaintext buffer
    fn open(
        &self,
        buf: &mut [u8],
        cipher_len: usize,
        ad: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>>;

    /// Opens the Ciphertext and returns the plaintext length using AEAD. `buf` contains the outgoing
    /// plaintext buffer
    fn open_to(
        &self,
        buf: &mut [u8],
        cipher: &[u8],
        ad: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>>;
}
