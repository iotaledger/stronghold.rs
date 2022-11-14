// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crypto::{
    ciphers::{chacha::XChaCha20Poly1305, traits::Aead},
    utils::rand::fill,
};

use engine::vault::{BoxProvider, Key};
use zeroize::Zeroize;
#[derive(Ord, PartialEq, Eq, PartialOrd, Zeroize, Clone)]
pub struct Provider;
impl Provider {
    const NONCE_LEN: usize = XChaCha20Poly1305::NONCE_LENGTH;
    const TAG_LEN: usize = XChaCha20Poly1305::TAG_LENGTH;
}

impl BoxProvider for Provider {
    type Error = crypto::Error;

    fn box_key_len() -> usize {
        32
    }

    fn box_overhead() -> usize {
        Self::NONCE_LEN + Self::TAG_LEN
    }

    fn box_seal(key: &Key<Self>, ad: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let mut cipher = vec![0u8; data.len()];

        let mut tag = vec![0u8; 16];
        let mut nonce: [u8; 24] = [0u8; Self::NONCE_LEN];

        Self::random_buf(&mut nonce)?;

        let key = &key.key;

        XChaCha20Poly1305::try_encrypt(&key.borrow(), &nonce, ad, data, &mut cipher, &mut tag)?;

        let r#box = [tag.to_vec(), nonce.to_vec(), cipher].concat();

        Ok(r#box)
    }

    fn box_open(key: &Key<Self>, ad: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let (tag, ct) = data.split_at(Self::TAG_LEN);
        let (nonce, cipher) = ct.split_at(Self::NONCE_LEN);

        let mut plain = vec![0; cipher.len()];

        let key = &key.key;

        XChaCha20Poly1305::try_decrypt(&key.borrow(), nonce, ad, &mut plain, cipher, tag)?;

        Ok(plain)
    }

    fn random_buf(buf: &mut [u8]) -> Result<(), Self::Error> {
        fill(buf)
    }
}
