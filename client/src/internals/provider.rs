// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crypto::{
    ciphers::{chacha::XChaCha20Poly1305, traits::Aead},
    utils::rand::fill,
};

use std::convert::TryInto;

use engine::vault::{self, BoxProvider, Key};
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

        XChaCha20Poly1305::encrypt(
            key.as_slice().try_into().expect("Key not the correct size: Encrypt"),
            &nonce.try_into().expect("Nonce not the correct size: Encrypt"),
            ad,
            data,
            &mut cipher,
            tag.as_mut_slice().try_into().expect(""),
        )
        .map_err(|_| vault::Error::CryptoError(String::from("Unable to seal data")))?;

        let r#box = [tag.to_vec(), nonce.to_vec(), cipher].concat();

        Ok(r#box)
    }

    fn box_open(key: &Key<Self>, ad: &[u8], data: &[u8]) -> vault::Result<Vec<u8>> {
        let (tag, ct) = data.split_at(Self::TAG_LEN);
        let (nonce, cipher) = ct.split_at(Self::NONCE_LEN);

        let mut plain = vec![0; cipher.len()];

        let key = key.bytes();

        XChaCha20Poly1305::decrypt(
            key.as_slice().try_into().expect("Key not the correct size: Encrypt"),
            nonce.try_into().expect("Nonce not the correct size: Encrypt"),
            ad,
            tag.try_into().expect("Tag not the correct size: Encrypt"),
            &cipher,
            &mut plain,
        )
        .map_err(|_| vault::Error::CryptoError(String::from("Unable to unlock data")))?;

        Ok(plain)
    }

    fn random_buf(buf: &mut [u8]) -> vault::Result<()> {
        fill(buf).map_err(|_| vault::Error::CryptoError(String::from("Can't generate random Bytes")))
    }
}
