// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crypto::{
    ciphers::{chacha::XChaCha20Poly1305, traits::Aead},
    utils::rand::fill,
};

use engine::vault::{self, BoxProvider, Key};
/// An implementation of the Vault's `BoxProvider type.  Used to encrypt and decrypt the data in this Stronghold.
#[derive(Ord, PartialEq, Eq, PartialOrd, Clone, Debug)]
pub struct Provider;
impl Provider {
    const NONCE_LEN: usize = XChaCha20Poly1305::NONCE_LENGTH;
    const TAG_LEN: usize = XChaCha20Poly1305::TAG_LENGTH;
}

impl BoxProvider for Provider {
    fn box_key_len() -> usize {
        32
    }

    fn box_overhead() -> usize {
        Self::NONCE_LEN + Self::TAG_LEN
    }

    fn box_seal(key: &Key<Self>, ad: &[u8], data: &[u8]) -> vault::Result<Vec<u8>> {
        let mut cipher = vec![0u8; data.len()];

        let mut tag = vec![0u8; 16];
        let mut nonce: [u8; 24] = [0u8; Self::NONCE_LEN];

        Self::random_buf(&mut nonce)?;

        let key = key.bytes();

        XChaCha20Poly1305::try_encrypt(&key, &nonce, ad, data, &mut cipher, &mut tag)
            .map_err(|_| vault::Error::CryptoError(String::from("Unable to seal data")))?;

        let r#box = [tag.to_vec(), nonce.to_vec(), cipher].concat();

        Ok(r#box)
    }

    fn box_open(key: &Key<Self>, ad: &[u8], data: &[u8]) -> vault::Result<Vec<u8>> {
        let (tag, ct) = data.split_at(Self::TAG_LEN);
        let (nonce, cipher) = ct.split_at(Self::NONCE_LEN);

        let mut plain = vec![0; cipher.len()];

        let key = key.bytes();

        XChaCha20Poly1305::try_decrypt(&key, &nonce, &ad, &mut plain, &cipher, &tag)
            .map_err(|_| vault::Error::CryptoError(String::from("Unable to unlock data")))?;

        Ok(plain)
    }

    fn random_buf(buf: &mut [u8]) -> vault::Result<()> {
        fill(buf).map_err(|_| vault::Error::CryptoError(String::from("Can't generate random Bytes")))
    }
}
