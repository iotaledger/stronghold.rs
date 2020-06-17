use std::{error::Error, ops::Range};

use crate::rng::SecretKeyGen;

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct CipherInfo {
    pub id: &'static str,
    pub one_time: bool,
    pub key_lens: Range<usize>,
    pub nonce_lens: Range<usize>,
    pub tag_lens: Range<usize>,
}

pub trait Cipher: SecretKeyGen {
    fn info(&self) -> CipherInfo;
    fn predict_encrypted_max(&self, plain_len: usize) -> usize;
    fn encrypt(
        &self,
        buf: &mut [u8],
        plain: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>>;

    fn decrypt(
        &self,
        buf: &mut [u8],
        cipher_len: usize,
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>>;

    fn decrypt_to(
        &self,
        buf: &mut [u8],
        cipher: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>>;
}

pub trait AeadCipher: Cipher {
    fn seal(
        &self,
        buf: &mut [u8],
        plain_len: usize,
        ad: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>>;

    fn seal_to(
        &self,
        buf: &mut [u8],
        plain: &[u8],
        ad: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>>;

    fn open(
        &self,
        buf: &mut [u8],
        cipher_len: usize,
        ad: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>>;
    fn open_to(
        &self,
        buf: &mut [u8],
        cipher: &[u8],
        ad: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>>;
}
