use crate::{
    chacha_ietf::CHACHA20_KEY,
    internal::chacha::{chacha20_block, h_chacha20_hash},
};
use primitives::{
    cipher::{Cipher, CipherInfo},
    rng::{SecretKeyGen, SecureRng},
};
use std::{cmp::min, error::Error};

/// max bytes that can be processed with a key/nonce combo
pub const XCHACHA20_MAX: usize = usize::max_value();
/// size of the key
pub const XCHACHA20_KEY: usize = CHACHA20_KEY;
/// size of the nonce
pub const XCHACHA20_NONCE: usize = 24;

pub struct XChaCha20;
impl XChaCha20 {
    /// builds a new Cipher with XChaCha20
    pub fn cipher() -> Box<dyn Cipher> {
        Box::new(Self)
    }

    /// Xor the bytes with XChaCha20 kestream.
    pub fn xor(key: &[u8], nonce: &[u8], mut n: u64, mut data: &mut [u8]) {
        // check input
        assert_eq!(XCHACHA20_KEY, key.len());
        assert_eq!(XCHACHA20_NONCE, nonce.len());

        // derive key
        let (x_nonce, nonce) = nonce.split_at(16);
        let mut x_key = vec![0; 32];
        h_chacha20_hash(key, x_nonce, &mut x_key);

        // XOR data
        let mut buf = vec![0; 64];
        while !data.is_empty() {
            // Calculate next block
            chacha20_block(&x_key, nonce, n, &mut buf);
            n = n
                .checked_add(1)
                .expect("The ChaCha20 block counter must not exceed 2^64 - 1");

            // XOR blocks
            let to_xor = min(data.len(), buf.len());
            (0..to_xor).for_each(|i| data[i] = xor!(data[i], buf[i]));
            data = &mut data[to_xor..];
        }
    }
}
impl SecretKeyGen for XChaCha20 {
    fn new_secret_key(&self, buf: &mut [u8], rng: &mut dyn SecureRng) -> Result<usize, Box<dyn Error + 'static>> {
        verify_keygen!(XCHACHA20_KEY => buf);

        rng.random(&mut buf[..XCHACHA20_KEY])?;
        Ok(XCHACHA20_KEY)
    }
}

#[allow(clippy::reversed_empty_ranges)]
impl Cipher for XChaCha20 {
    fn info(&self) -> CipherInfo {
        CipherInfo {
            id: "XChaCha20",
            one_time: true,
            key_lens: XCHACHA20_KEY..XCHACHA20_KEY,
            nonce_lens: XCHACHA20_NONCE..XCHACHA20_NONCE,
            tag_lens: 0..0,
        }
    }

    fn predict_encrypted_max(&self, plain_len: usize) -> usize {
        plain_len
    }

    fn encrypt(
        &self,
        buf: &mut [u8],
        plain_len: usize,
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>> {
        verify_encrypt!(
            key => [XCHACHA20_KEY], nonce => [XCHACHA20_NONCE],
            plain_len => [buf, XCHACHA20_MAX]
        );

        Self::xor(key, nonce, 0, &mut buf[..plain_len]);
        Ok(plain_len)
    }
    fn encrypt_to(
        &self,
        buf: &mut [u8],
        plain: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>> {
        verify_encrypt!(
            key => [XCHACHA20_KEY], nonce => [XCHACHA20_NONCE],
            plain => [buf, XCHACHA20_MAX]
        );

        buf[..plain.len()].copy_from_slice(plain);
        Self::xor(key, nonce, 0, &mut buf[..plain.len()]);
        Ok(plain.len())
    }

    fn decrypt(
        &self,
        buf: &mut [u8],
        cipher_len: usize,
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>> {
        verify_decrypt!(
            key => [XCHACHA20_KEY], nonce => [XCHACHA20_NONCE],
            cipher_len => [buf, XCHACHA20_MAX]
        );

        Self::xor(key, nonce, 0, &mut buf[..cipher_len]);
        Ok(cipher_len)
    }
    fn decrypt_to(
        &self,
        buf: &mut [u8],
        cipher: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>> {
        verify_decrypt!(
            key => [XCHACHA20_KEY], nonce => [XCHACHA20_NONCE],
            cipher => [buf, XCHACHA20_MAX]
        );

        buf[..cipher.len()].copy_from_slice(cipher);
        Self::xor(key, nonce, 0, &mut buf[..cipher.len()]);
        Ok(cipher.len())
    }
}
