// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crypto::XChaChaPoly;

use random::{
    primitives::{cipher::AeadCipher, rng::SecureRng},
    OsRng,
};

use vault::{BoxProvider, Key};

pub struct Provider;
impl Provider {
    const NONCE_LEN: usize = 24;
    const TAG_LEN: usize = 16;
}

impl BoxProvider for Provider {
    fn box_key_len() -> usize {
        32
    }

    fn box_overhead() -> usize {
        Self::NONCE_LEN + Self::TAG_LEN
    }

    fn box_seal(key: &Key<Self>, ad: &[u8], data: &[u8]) -> vault::Result<Vec<u8>> {
        let mut boxx = vec![0; data.len() + Self::box_overhead()];
        let (nonce, cipher) = boxx.split_at_mut(Self::NONCE_LEN);
        Self::random_buf(nonce)?;

        XChaChaPoly
            .seal_with(cipher, data, ad, key.bytes(), nonce)
            .map_err(|_| vault::Error::CryptoError(String::from("Unable to seal data")))?;
        Ok(boxx)
    }
    fn box_open(key: &Key<Self>, ad: &[u8], data: &[u8]) -> vault::Result<Vec<u8>> {
        let mut plain = match data.len() {
            len if len >= Self::box_overhead() => vec![0; len - Self::box_overhead()],
            _ => return Err(vault::Error::CryptoError(String::from("Truncated cipher"))),
        };

        let (nonce, cipher) = data.split_at(Self::NONCE_LEN);

        XChaChaPoly
            .open_to(&mut plain, cipher, ad, key.bytes(), nonce)
            .map_err(|_| vault::Error::CryptoError(String::from("Invalid Cipher")))?;

        Ok(plain)
    }

    fn random_buf(buf: &mut [u8]) -> vault::Result<()> {
        OsRng
            .random(buf)
            .map_err(|_| vault::Error::CryptoError(String::from("Can't generated random Bytes")))
    }
}
