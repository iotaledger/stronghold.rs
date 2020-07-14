use std::{error::Error, ops::Range};

use crate::rng::SecretKeyGen;

// Information about the Cipher implementations
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct CipherInfo {
    // the cipher id or label
    pub id: &'static str,
    // is the cipher a one time cipher?
    pub one_time: bool,

    // supported key lengths
    pub key_lens: Range<usize>,
    // supported nonce lengths
    pub nonce_lens: Range<usize>,
    // supported AEAD tag lengths. Without AEAD defaults to 0..0
    pub tag_lens: Range<usize>,
}

// A one shot stateless cipher interface
pub trait Cipher: SecretKeyGen {
    // returns cipher info
    fn info(&self) -> CipherInfo;
    // predicts the max encrypted length for a plaintext len in bytes
    fn predict_encrypted_max(&self, plain_len: usize) -> usize;
    // encrypts the plaintext length in-place and returns the cipher's length.
    fn encrypt(
        &self,
        buf: &mut [u8],
        plain_len: usize,
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>>;

    // encrypts the plainttext and returns the plaintext's length.
    fn encrypt_to(
        &self,
        buf: &mut [u8],
        plain: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>>;

    // decrypts the cipher length bytes in-place and returns the plaintext length.
    fn decrypt(
        &self,
        buf: &mut [u8],
        cipher_len: usize,
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>>;

    // decrypts the ciphertext and returns the plaintext's length.
    fn decrypt_to(
        &self,
        buf: &mut [u8],
        cipher: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>>;
}

// an AEAD Extension for the Cipher Trait
pub trait AeadCipher: Cipher {
    // Seals the Plaintext bytes in place with AEAD and returns the Cipher length.
    fn seal(
        &self,
        buf: &mut [u8],
        plain_len: usize,
        ad: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>>;

    // Seals the plaintext and returns the Cipher's length using AEAD
    fn seal_with(
        &self,
        buf: &mut [u8],
        plain: &[u8],
        ad: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>>;

    // Opens the Ciphertext length in-place and returns the plaintext length using AEAD.
    fn open(
        &self,
        buf: &mut [u8],
        cipher_len: usize,
        ad: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>>;

    // Opens the Ciphertext and returns the plaintext length using AEAD.
    fn open_to(
        &self,
        buf: &mut [u8],
        cipher: &[u8],
        ad: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>>;
}
