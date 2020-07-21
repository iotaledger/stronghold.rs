use crate::internal::chacha::chacha20_ietf_block;
use primitives::{
    cipher::{Cipher, CipherInfo},
    rng::{SecretKeyGen, SecureRng},
};
use std::{cmp::min, error::Error};

/// max bytes that can be processed with a key/nonce combo
#[cfg(target_pointer_width = "64")]
pub const CHACHA20_MAX: usize = 4_294_967_296 * 64;
#[cfg(target_pointer_width = "32")]
pub const CHACHA20_MAX: usize = usize::max_value();
/// Size of Key
pub const CHACHA20_KEY: usize = 32;
/// Size of Nonce
pub const CHACHA20_NONCE: usize = 12;

pub struct ChaCha20Ietf;
impl ChaCha20Ietf {
    /// create a new Cipher with ChaCha20IETF
    pub fn cipher() -> Box<dyn Cipher> {
        Box::new(Self)
    }

    /// Xor data with ChaCha20 keystream
    pub fn xor(key: &[u8], nonce: &[u8], mut n: u32, mut data: &mut [u8]) {
        // verify inputs
        assert_eq!(CHACHA20_KEY, key.len());
        assert_eq!(CHACHA20_NONCE, nonce.len());

        // xor the data
        let mut buf = vec![0; 64];
        while !data.is_empty() {
            // compute blocks
            chacha20_ietf_block(key, nonce, n, &mut buf);
            n = n
                .checked_add(1)
                .expect("The ChaCha20-IETF block counter must not exceed 2^32 - 1");

            // xor blocks
            let to_xor = min(data.len(), buf.len());
            (0..to_xor).for_each(|i| data[i] = xor!(data[i], buf[i]));
            data = &mut data[to_xor..];
        }
    }
}
impl SecretKeyGen for ChaCha20Ietf {
    fn new_secret_key(&self, buf: &mut [u8], rng: &mut dyn SecureRng) -> Result<usize, Box<dyn Error + 'static>> {
        verify_keygen!(CHACHA20_KEY => buf);

        rng.random(&mut buf[..CHACHA20_KEY])?;
        Ok(CHACHA20_KEY)
    }
}

#[allow(clippy::reversed_empty_ranges)]
impl Cipher for ChaCha20Ietf {
    fn info(&self) -> CipherInfo {
        CipherInfo {
            id: "ChaCha20Ietf",
            one_time: true,
            key_lens: CHACHA20_KEY..CHACHA20_KEY,
            nonce_lens: CHACHA20_NONCE..CHACHA20_NONCE,
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
            key => [CHACHA20_KEY], nonce => [CHACHA20_NONCE],
            plain_len => [buf, CHACHA20_MAX]
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
            key => [CHACHA20_KEY], nonce => [CHACHA20_NONCE],
            plain => [buf, CHACHA20_MAX]
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
            key => [CHACHA20_KEY], nonce => [CHACHA20_NONCE],
            cipher_len => [buf, CHACHA20_MAX]
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
            key => [CHACHA20_KEY], nonce => [CHACHA20_NONCE],
            cipher => [buf, CHACHA20_MAX]
        );

        buf[..cipher.len()].copy_from_slice(cipher);
        Self::xor(key, nonce, 0, &mut buf[..cipher.len()]);
        Ok(cipher.len())
    }
}
