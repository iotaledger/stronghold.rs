use crate::{
    chachapoly_ietf::{CHACHAPOLY_KEY, CHACHAPOLY_MAX, CHACHAPOLY_TAG},
    poly::Poly1305,
    xchacha::XChaCha20,
};
use primitives::{
    cipher::{AeadCipher, Cipher, CipherInfo},
    rng::{SecretKeyGen, SecureRng},
};

use std::error::Error;

/// max bytes that can be processed with a key/nonce combo
#[allow(unused)]
pub const XCHACHAPOLY_MAX: usize = CHACHAPOLY_MAX;
/// size of the key
pub const XCHACHAPOLY_KEY: usize = CHACHAPOLY_KEY;
/// size of the nonce
pub const XCHACHAPOLY_NONCE: usize = 24;
/// size of the auth tag
pub const XCHACHAPOLY_TAG: usize = CHACHAPOLY_TAG;

/// encrypts data in-place and authenticates it
fn xchachapoly_seal(data: &mut [u8], tag: &mut [u8], ad: &[u8], key: &[u8], nonce: &[u8]) {
    // xor and encrypt the data.
    XChaCha20::xor(key, nonce, 1, data);

    // build a footer
    let mut foot = Vec::with_capacity(16);
    foot.extend_from_slice(&(ad.len() as u64).to_le_bytes());
    foot.extend_from_slice(&(data.len() as u64).to_le_bytes());

    // compute Poly1305 key and auth tag
    let mut pkey = vec![0; 32];
    XChaCha20::xor(key, nonce, 0, &mut pkey);
    Poly1305::chachapoly_auth(tag, ad, data, &foot, &pkey);
}

/// decrypts data in-place after validation
fn xchachapoly_open(
    data: &mut [u8],
    tag: &[u8],
    ad: &[u8],
    key: &[u8],
    nonce: &[u8],
) -> Result<(), Box<dyn Error + 'static>> {
    // build footer
    let mut foot = Vec::with_capacity(16);
    foot.extend_from_slice(&(ad.len() as u64).to_le_bytes());
    foot.extend_from_slice(&(data.len() as u64).to_le_bytes());

    // get poly1305 key and auth tag
    let (mut pkey, mut verify_tag) = (vec![0; 32], vec![0; 16]);
    XChaCha20::xor(key, nonce, 0, &mut pkey);
    Poly1305::chachapoly_auth(&mut verify_tag, ad, data, &foot, &pkey);

    // validate the tags.
    if !eq_const_time!(&tag, &verify_tag) {
        return Err(crate::Error::InvalidData.into());
    }
    XChaCha20::xor(key, nonce, 1, data);
    Ok(())
}

/// XChaChaPoly Cipher
pub struct XChaChaPoly;

impl XChaChaPoly {
    // builds a new Cipher with XChaChaPolyIETF
    pub fn cipher() -> Box<dyn Cipher> {
        Box::new(Self)
    }

    // builds an AEAD Cipher with XChaChaPolyIETF
    pub fn aead_cipher() -> Box<dyn AeadCipher> {
        Box::new(Self)
    }
}
impl SecretKeyGen for XChaChaPoly {
    /// generate a new secret key
    fn new_secret_key(&self, buf: &mut [u8], rng: &mut dyn SecureRng) -> Result<usize, Box<dyn Error + 'static>> {
        // validate input
        verify_keygen!(XCHACHAPOLY_KEY => buf);

        // generate key
        rng.random(&mut buf[..XCHACHAPOLY_KEY])?;
        Ok(XCHACHAPOLY_KEY)
    }
}

#[allow(clippy::reversed_empty_ranges)]
impl Cipher for XChaChaPoly {
    fn info(&self) -> CipherInfo {
        CipherInfo {
            id: "XChachaPoly",
            one_time: true,
            key_lens: XCHACHAPOLY_KEY..XCHACHAPOLY_KEY,
            nonce_lens: XCHACHAPOLY_NONCE..XCHACHAPOLY_NONCE,
            tag_lens: XCHACHAPOLY_TAG..XCHACHAPOLY_TAG,
        }
    }

    fn predict_encrypted_max(&self, plain_len: usize) -> usize {
        plain_len + 16
    }

    fn encrypt(
        &self,
        buf: &mut [u8],
        plain_len: usize,
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>> {
        self.seal(buf, plain_len, &[], key, nonce)
    }
    fn encrypt_to(
        &self,
        buf: &mut [u8],
        plain: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>> {
        self.seal_with(buf, plain, &[], key, nonce)
    }

    fn decrypt(
        &self,
        buf: &mut [u8],
        cipher_len: usize,
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>> {
        self.open(buf, cipher_len, &[], key, nonce)
    }
    fn decrypt_to(
        &self,
        buf: &mut [u8],
        cipher: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>> {
        self.open_to(buf, cipher, &[], key, nonce)
    }
}
impl AeadCipher for XChaChaPoly {
    fn seal(
        &self,
        buf: &mut [u8],
        plain_len: usize,
        ad: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>> {
        verify_seal!(
            key => [XCHACHAPOLY_KEY], nonce => [XCHACHAPOLY_NONCE],
            plain_len => [buf, XCHACHAPOLY_MAX]
        );

        let (data, tag) = buf.split_at_mut(plain_len);
        xchachapoly_seal(data, &mut tag[..XCHACHAPOLY_TAG], ad, key, nonce);
        Ok(plain_len + XCHACHAPOLY_TAG)
    }
    fn seal_with(
        &self,
        buf: &mut [u8],
        plain: &[u8],
        ad: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>> {
        verify_seal!(
            key => [XCHACHAPOLY_KEY], nonce => [XCHACHAPOLY_NONCE],
            plain => [buf, XCHACHAPOLY_MAX]
        );

        let (data, tag) = buf.split_at_mut(plain.len());
        data.copy_from_slice(plain);
        xchachapoly_seal(data, &mut tag[..XCHACHAPOLY_TAG], ad, key, nonce);
        Ok(plain.len() + XCHACHAPOLY_TAG)
    }

    fn open(
        &self,
        buf: &mut [u8],
        cipher_len: usize,
        ad: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>> {
        verify_open!(
            key => [XCHACHAPOLY_KEY], nonce => [XCHACHAPOLY_NONCE],
            cipher_len => [buf, XCHACHAPOLY_TAG, XCHACHAPOLY_MAX]
        );

        let (data, tag) = buf.split_at_mut(cipher_len - XCHACHAPOLY_TAG);
        xchachapoly_open(data, &tag[..XCHACHAPOLY_TAG], ad, key, nonce)?;
        Ok(cipher_len - XCHACHAPOLY_TAG)
    }
    fn open_to(
        &self,
        buf: &mut [u8],
        cipher: &[u8],
        ad: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>> {
        verify_open!(
            key => [XCHACHAPOLY_KEY], nonce => [XCHACHAPOLY_NONCE],
            cipher => [buf, XCHACHAPOLY_TAG, XCHACHAPOLY_MAX]
        );

        let (data, tag) = cipher.split_at(cipher.len() - XCHACHAPOLY_TAG);
        buf[..data.len()].copy_from_slice(data);
        xchachapoly_open(&mut buf[..data.len()], &tag[..XCHACHAPOLY_TAG], ad, key, nonce)?;
        Ok(cipher.len() - XCHACHAPOLY_TAG)
    }
}
