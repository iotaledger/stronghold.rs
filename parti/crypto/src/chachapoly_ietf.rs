use crate::{chacha_ietf::ChaCha20Ietf, poly::Poly1305};
use primitives::{
    cipher::{AeadCipher, Cipher, CipherInfo},
    rng::{SecretKeyGen, SecureRng},
};
use std::error::Error;
// max bytes that can be processed with a key/nonce combo
#[cfg(target_pointer_width = "64")]
pub const CHACHAPOLY_MAX: usize = (4_294_967_296 - 1) * 64;
#[cfg(target_pointer_width = "32")]
pub const CHACHAPOLY_MAX: usize = usize::max_value() - 16;

// size of key
pub const CHACHAPOLY_KEY: usize = 32;
// size of nonce
pub const CHACHAPOLY_NONCE: usize = 12;
// size of auth tag
pub const CHACHAPOLY_TAG: usize = 16;

// encrypts data in place
pub fn chachapoly_seal(data: &mut [u8], tag: &mut [u8], ad: &[u8], key: &[u8], nonce: &[u8]) {
    // encrypt data
    ChaCha20Ietf::xor(key, nonce, 1, data);

    // create footer
    let mut foot = Vec::with_capacity(16);
    foot.extend_from_slice(&(ad.len() as u64).to_le_bytes());
    foot.extend_from_slice(&(data.len() as u64).to_le_bytes());

    // compute poly key and auth tag
    let mut pkey = vec![0; 32];
    ChaCha20Ietf::xor(key, nonce, 0, &mut pkey);
    Poly1305::chachapoly_auth(tag, ad, data, &foot, &pkey);
}

// open data and decrypt it in place.
pub fn chachapoly_open(
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

    // compute poly key and auth tag
    let (mut pkey, mut vfy_tag) = (vec![0; 32], vec![0; 16]);
    ChaCha20Ietf::xor(key, nonce, 0, &mut pkey);
    Poly1305::chachapoly_auth(&mut vfy_tag, ad, data, &foot, &pkey);

    // validate tags
    if eq_const_time!(&tag, &vfy_tag) {
        Ok(ChaCha20Ietf::xor(key, nonce, 1, data))
    }else{
        Err(crate::Error::InvalidData)?
    }
}

pub struct ChaChaPolyIetf;
impl ChaChaPolyIetf {
    // create a new Cipher with ChaChaPolyIETF
    pub fn cipher() -> Box<dyn Cipher> {
        Box::new(Self)
    }
    // create a new AEAD Cipher with ChaChaPolyIETF
    pub fn aead_cipher() -> Box<dyn AeadCipher> {
        Box::new(Self)
    }
}
impl SecretKeyGen for ChaChaPolyIetf {
    fn new_secret_key(
        &self,
        buf: &mut [u8],
        rng: &mut dyn SecureRng,
    ) -> Result<usize, Box<dyn Error + 'static>> {
        verify_keygen!(CHACHAPOLY_KEY => buf);

        rng.random(&mut buf[..CHACHAPOLY_KEY])?;
        Ok(CHACHAPOLY_KEY)
    }
}
impl Cipher for ChaChaPolyIetf {
    fn info(&self) -> CipherInfo {
        CipherInfo {
            id: "ChaChaPolyIetf",
            one_time: true,
            key_lens: CHACHAPOLY_KEY..CHACHAPOLY_KEY,
            nonce_lens: CHACHAPOLY_NONCE..CHACHAPOLY_NONCE,
            tag_lens: CHACHAPOLY_TAG..CHACHAPOLY_TAG,
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
impl AeadCipher for ChaChaPolyIetf {
    fn seal(
        &self,
        buf: &mut [u8],
        plain_len: usize,
        ad: &[u8],
        key: &[u8],
        nonce: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>> {
        verify_seal!(
            key => [CHACHAPOLY_KEY], nonce => [CHACHAPOLY_NONCE],
            plain_len => [buf, CHACHAPOLY_MAX]
        );

        let (data, tag) = buf.split_at_mut(plain_len);
        chachapoly_seal(data, &mut tag[..CHACHAPOLY_TAG], ad, key, nonce);
        Ok(plain_len + CHACHAPOLY_TAG)
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
            key => [CHACHAPOLY_KEY], nonce => [CHACHAPOLY_NONCE],
            plain => [buf, CHACHAPOLY_MAX]
        );

        let (data, tag) = buf.split_at_mut(plain.len());
        data.copy_from_slice(plain);
        chachapoly_seal(data, &mut tag[..CHACHAPOLY_TAG], ad, key, nonce);
        Ok(plain.len() + CHACHAPOLY_TAG)
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
            key => [CHACHAPOLY_KEY], nonce => [CHACHAPOLY_NONCE],
            cipher_len => [buf, CHACHAPOLY_TAG, CHACHAPOLY_MAX]
        );

        let (data, tag) = buf.split_at_mut(cipher_len - CHACHAPOLY_TAG);
        chachapoly_open(data, &tag[..CHACHAPOLY_TAG], ad, key, nonce)?;
        Ok(cipher_len - CHACHAPOLY_TAG)
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
            key => [CHACHAPOLY_KEY], nonce => [CHACHAPOLY_NONCE],
            cipher => [buf, CHACHAPOLY_TAG, CHACHAPOLY_MAX]
        );

        let (data, tag) = cipher.split_at(cipher.len() - CHACHAPOLY_TAG);
        buf[..data.len()].copy_from_slice(data);
        chachapoly_open(
            &mut buf[..data.len()],
            &tag[..CHACHAPOLY_TAG],
            ad,
            key,
            nonce,
        )?;
        Ok(cipher.len() - CHACHAPOLY_TAG)
    }
}
