use crate::{
    chachapoly_ietf::{ChachaPolyIetf, CHACHAPOLY_KEY, CHACHAPOLY_MAX, CHACHAPOLY_TAG},
    poly::Poly1305,
    xchacha::XChaCha20,
};
use primitives::{
    cipher::{AeadCipher, Cipher, CipherInfo},
    rng::{SecretKeyGen, SecureRng},
};

use std::error::Error;

#[allow(unused)]
pub const XCHACHAPOLY_MAX: usize = CHACHAPOLY_MAX;

pub const XCHACHAPOLY_KEY: usize = CHACHAPOLY_KEY;
pub const XCHACHAPOLY_NONCE: usize = 24;
pub const XCHACHAPOLY_TAG: usize = CHACHAPOLY_TAG;

fn xchachapoly_seal(data: &mut [u8], tag: &mut [u8], ad: &[u8], key: &[u8], nonce: &[u8]) {
    XChaCha20::xor(key, nonce, 1, data);

    let mut foot = Vec::with_capacity(16);
    foot.extend_from_slice(&(ad.len() as u64).to_le_bytes());
    foot.extend_from_slice(&(data.len() as u64).to_le_bytes());

    let mut pkey = vec![0; 32];
    XChaCha20::xor(key, nonce, 0, &mut pkey);
    Poly1305::chachapoly_auth(tag, ad, data, &foot, &pkey);
}

fn xchachapoly_open(
    data: &mut [u8],
    tag: &[u8],
    ad: &[u8],
    key: &[u8],
    nonce: &[u8],
) -> Result<(), Box<dyn Error + 'static>> {
    let mut foot = Vec::with_capacity(16);
    foot.extend_from_slice(&(ad.len() as u64).to_le_bytes());
    foot.extend_from_slice(&(data.len() as u64).to_le_bytes());

    let (mut pkey, mut verify_tag) = (vec![0; 32], vec![0; 16]);
    XChaCha20::xor(key, nonce, 0, &mut pkey);
    Poly1305::chachapoly_auth(&mut verify_tag, ad, data, &foot, &pkey);

    Ok(match eq_const_time!(&tag, &verify_tag) {
        true => XChaCha20::xor(key, nonce, 1, data),
        false => Err(crate::Error::InvalidData)?,
    })
}

pub struct XChaChaPoly;

impl XChaChaPoly {
    pub fn cipher() -> Box<dyn Cipher> {
        Box::new(Self)
    }

    pub fn aead_cipher() -> Box<dyn AeadCipher> {
        Box::new(Self)
    }
}
impl SecretKeyGen for XChaChaPoly {
    fn new_secret_key(
        &self,
        buf: &mut [u8],
        rng: &mut dyn SecureRng,
    ) -> Result<usize, Box<dyn Error + 'static>> {
        verify_keygen!(XCHACHAPOLY_KEY => buf);

        rng.random(&mut buf[..XCHACHAPOLY_KEY])?;
        Ok(XCHACHAPOLY_KEY)
    }
}
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

    fn predict_encrypted_max(&self, plaintext_len: usize) -> usize {
        plaintext_len + 16
    }

    fn encrypt(
        &self,
        buf: &mut [u8],
        plaintext_len: usize,
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>> {
        self.seal(buf, plaintext_len, &[], key, nonce)
    }
    fn encrypt_to(
        &self,
        buf: &mut [u8],
        plaintext: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>> {
        self.seal_with(buf, plaintext, &[], key, nonce)
    }

    fn decrypt(
        &self,
        buf: &mut [u8],
        ciphertext_len: usize,
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>> {
        self.open(buf, ciphertext_len, &[], key, nonce)
    }
    fn decrypt_to(
        &self,
        buf: &mut [u8],
        ciphertext: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>> {
        self.open_to(buf, ciphertext, &[], key, nonce)
    }
}
impl AeadCipher for XChaChaPoly {
    fn seal(
        &self,
        buf: &mut [u8],
        plaintext_len: usize,
        ad: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>> {
        verify_seal!(
            key => [XCHACHAPOLY_KEY], nonce => [XCHACHAPOLY_NONCE],
            plaintext_len => [buf, XCHACHAPOLY_MAX]
        );

        let (data, tag) = buf.split_at_mut(plaintext_len);
        xchachapoly_seal(data, &mut tag[..XCHACHAPOLY_TAG], ad, key, nonce);
        Ok(plaintext_len + XCHACHAPOLY_TAG)
    }
    fn seal_with(
        &self,
        buf: &mut [u8],
        plaintext: &[u8],
        ad: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>> {
        verify_seal!(
            key => [XCHACHAPOLY_KEY], nonce => [XCHACHAPOLY_NONCE],
            plaintext => [buf, XCHACHAPOLY_MAX]
        );

        let (data, tag) = buf.split_at_mut(plaintext.len());
        data.copy_from_slice(plaintext);
        xchachapoly_seal(data, &mut tag[..XCHACHAPOLY_TAG], ad, key, nonce);
        Ok(plaintext.len() + XCHACHAPOLY_TAG)
    }

    fn open(
        &self,
        buf: &mut [u8],
        ciphertext_len: usize,
        ad: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>> {
        verify_open!(
            key => [XCHACHAPOLY_KEY], nonce => [XCHACHAPOLY_NONCE],
            ciphertext_len => [buf, XCHACHAPOLY_TAG, XCHACHAPOLY_MAX]
        );

        let (data, tag) = buf.split_at_mut(ciphertext_len - XCHACHAPOLY_TAG);
        xchachapoly_open(data, &tag[..XCHACHAPOLY_TAG], ad, key, nonce)?;
        Ok(ciphertext_len - XCHACHAPOLY_TAG)
    }
    fn open_to(
        &self,
        buf: &mut [u8],
        ciphertext: &[u8],
        ad: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>> {
        verify_open!(
            key => [XCHACHAPOLY_KEY], nonce => [XCHACHAPOLY_NONCE],
            ciphertext => [buf, XCHACHAPOLY_TAG, XCHACHAPOLY_MAX]
        );

        let (data, tag) = ciphertext.split_at(ciphertext.len() - XCHACHAPOLY_TAG);
        buf[..data.len()].copy_from_slice(data);
        xchachapoly_open(
            &mut buf[..data.len()],
            &tag[..XCHACHAPOLY_TAG],
            ad,
            key,
            nonce,
        )?;
        Ok(ciphertext.len() - XCHACHAPOLY_TAG)
    }
}
