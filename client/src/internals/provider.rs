// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crypto::{ciphers::chacha::xchacha20poly1305, rand::fill};

use std::convert::TryInto;

use engine::vault::{BoxProvider, Key};
#[derive(Ord, PartialEq, Eq, PartialOrd, Clone, Debug)]
pub struct Provider;
impl Provider {
    const NONCE_LEN: usize = xchacha20poly1305::XCHACHA20POLY1305_NONCE_SIZE;
    const TAG_LEN: usize = xchacha20poly1305::XCHACHA20POLY1305_TAG_SIZE;
}

impl BoxProvider for Provider {
    fn box_key_len() -> usize {
        32
    }

    fn box_overhead() -> usize {
        Self::NONCE_LEN + Self::TAG_LEN
    }

    fn box_seal(key: &Key<Self>, ad: &[u8], data: &[u8]) -> engine::vault::Result<Vec<u8>> {
        let mut cipher = vec![0u8; data.len()];

        let mut tag = [0u8; 16];
        let mut nonce: [u8; 24] = [0u8; Self::NONCE_LEN];

        Self::random_buf(&mut nonce)?;

        xchacha20poly1305::encrypt(
            &mut cipher,
            &mut tag,
            data,
            key.bytes().try_into().expect("Key not the correct size: Encrypt"),
            &nonce,
            ad,
        )
        .map_err(|_| engine::vault::Error::CryptoError(String::from("Unable to seal data")))?;

        let boxx = [tag.to_vec(), nonce.to_vec(), cipher].concat();

        Ok(boxx)
    }

    fn box_open(key: &Key<Self>, ad: &[u8], data: &[u8]) -> engine::vault::Result<Vec<u8>> {
        let (tag, ct) = data.split_at(Self::TAG_LEN);
        let (nonce, cipher) = ct.split_at(Self::NONCE_LEN);

        let mut plain = vec![0; cipher.len()];

        xchacha20poly1305::decrypt(
            &mut plain,
            cipher,
            key.bytes().try_into().expect("key is not the correct size: Decrypt"),
            &tag.try_into().expect("Key not the correct size: Decrypt"),
            &nonce.to_vec().try_into().expect("Key not the correct size: Decrypt"),
            ad,
        )
        .map_err(|_| engine::vault::Error::CryptoError(String::from("Invalid Cipher")))?;

        Ok(plain)
    }

    fn random_buf(buf: &mut [u8]) -> engine::vault::Result<()> {
        fill(buf).map_err(|_| engine::vault::Error::CryptoError(String::from("Can't generate random Bytes")))
    }
}
