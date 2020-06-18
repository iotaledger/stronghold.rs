use crate::{
    chacha_ietf::CHACHA20_KEY,
    internal::chacha::{chacha20_block, h_chacha20_hash},
};
use primitives::{
    cipher::{Cipher, CipherInfo},
    rng::{SecretKeyGen, SecureRng},
};
use std::{cmp::min, error::Error};

pub const XCHACHA20_MAX: usize = usize::max_value();
pub const XCHACHA20_KEY: usize = CHACHA20_KEY;
pub const XCHACHA20_NONCE: usize = 24;

pub struct XChaCha20;
impl XChaCha20 {
    pub fn cipher() -> Box<dyn Cipher> {
        Box::new(Self)
    }

    pub fn xor(key: &[u8], nonce: &[u8], mut n: u64, mut data: &mut [u8]) {
        assert_eq!(XCHACHA20_KEY, key.len());
        assert_eq!(XCHACHA20_NONCE, nonce.len());

        let (x_nonce, nonce) = nonce.split_at(16);
        let mut x_key = vec![0; 32];
        h_chacha20_hash(key, x_nonce, &mut x_key);

        let mut buf = vec![0; 64];
        while !data.is_empty() {
            chacha20_block(&x_key, nonce, n, &mut buf);
            n = n
                .checked_add(1)
                .expect("The ChaCha20 block counter must not exceed 2^64 - 1");

            let to_xor = min(data.len(), buf.len());
            (0..to_xor).for_each(|i| data[i] = xor!(data[i], buf[i]));
            data = &mut data[to_xor..];
        }
    }
}
impl SecretKeyGen for XChaCha20 {
    fn new_secret_key(
        &self,
        buf: &mut [u8],
        rng: &mut dyn SecureRng,
    ) -> Result<usize, Box<dyn Error + 'static>> {
        verify_keygen!(XCHACHA20_KEY => buf);

        rng.random(&mut buf[..XCHACHA20_KEY])?;
        Ok(XCHACHA20_KEY)
    }
}
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

    fn predict_encrypted_max(&self, plaintext_len: usize) -> usize {
        plaintext_len
    }

    fn encrypt(
        &self,
        buf: &mut [u8],
        plaintext_len: usize,
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>> {
        verify_encrypt!(
            key => [XCHACHA20_KEY], nonce => [XCHACHA20_NONCE],
            plaintext_len => [buf, XCHACHA20_MAX]
        );

        Self::xor(key, nonce, 0, &mut buf[..plaintext_len]);
        Ok(plaintext_len)
    }
    fn encrypt_to(
        &self,
        buf: &mut [u8],
        plaintext: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>> {
        verify_encrypt!(
            key => [XCHACHA20_KEY], nonce => [XCHACHA20_NONCE],
            plaintext => [buf, XCHACHA20_MAX]
        );

        buf[..plaintext.len()].copy_from_slice(plaintext);
        Self::xor(key, nonce, 0, &mut buf[..plaintext.len()]);
        Ok(plaintext.len())
    }

    fn decrypt(
        &self,
        buf: &mut [u8],
        ciphertext_len: usize,
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>> {
        verify_decrypt!(
            key => [XCHACHA20_KEY], nonce => [XCHACHA20_NONCE],
            ciphertext_len => [buf, XCHACHA20_MAX]
        );

        Self::xor(key, nonce, 0, &mut buf[..ciphertext_len]);
        Ok(ciphertext_len)
    }
    fn decrypt_to(
        &self,
        buf: &mut [u8],
        ciphertext: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>> {
        verify_decrypt!(
            key => [XCHACHA20_KEY], nonce => [XCHACHA20_NONCE],
            ciphertext => [buf, XCHACHA20_MAX]
        );

        buf[..ciphertext.len()].copy_from_slice(ciphertext);
        Self::xor(key, nonce, 0, &mut buf[..ciphertext.len()]);
        Ok(ciphertext.len())
    }
}
