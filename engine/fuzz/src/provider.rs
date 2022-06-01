// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crypto::{
    ciphers::{chacha::XChaCha20Poly1305, traits::Aead},
    utils::rand::fill,
};

use engine::{
    vault::{BoxProvider, Key},
    Error,
};

#[derive(Ord, PartialEq, Eq, PartialOrd)]
pub struct Provider;
impl Provider {
    // const taken from: https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction
    const NONCE_LEN: usize = 24; // was 192 // XChaCha20Poly1305::XCHACHA20POLY1305_NONCE_SIZE; // but is defined as 24

    // constant taken from https://github.com/iotaledger/crypto.rs/blob/8c38a75dc95a736c90baa852131f0f9211d4246a/src/ciphers/chacha.rs
    const TAG_LEN: usize = 16; // XChaCha20Poly1305::XCHACHA20POLY1305_TAG_SIZE;
}

impl BoxProvider for Provider {
    fn box_key_len() -> usize {
        32
    }

    fn box_overhead() -> usize {
        Self::NONCE_LEN + Self::TAG_LEN
    }

    fn box_seal(key: &Key<Self>, ad: &[u8], data: &[u8]) -> Result<Vec<u8>, engine::Error> {
        let mut cipher = vec![0u8; data.len()];
        let mut tag = [0u8; Self::TAG_LEN];
        let mut nonce: [u8; Self::NONCE_LEN] = [0u8; Self::NONCE_LEN];

        Self::random_buf(&mut nonce)?;

        let key_bytes = &key.key;

        // conversion between types
        let _key = generic_array::GenericArray::from_slice(&*key_bytes.borrow());
        let _nonce = generic_array::GenericArray::from_mut_slice(&mut nonce);
        let _tag = generic_array::GenericArray::from_mut_slice(&mut tag);

        XChaCha20Poly1305::encrypt(_key, _nonce, ad, data, &mut cipher, _tag).map_err(|_| {
            Error::CryptoError(crypto::Error::CipherError {
                alg: "XChaCha20Poly1305: Unable to seal data",
            })
        })?;

        let boxx = [tag.to_vec(), nonce.to_vec(), cipher.as_slice().to_vec()].concat();

        Ok(boxx)
    }

    fn box_open(key: &Key<Self>, ad: &[u8], data: &[u8]) -> Result<Vec<u8>, engine::Error> {
        let (tag, ct) = data.split_at(Self::TAG_LEN);
        let (nonce, cipher) = ct.split_at(Self::NONCE_LEN);

        let mut plain = vec![0; cipher.len()];

        let key_bytes = &key.key;

        // conversion between types
        let _key = generic_array::GenericArray::from_slice(&*key_bytes.borrow());
        let _nonce = generic_array::GenericArray::from_slice(&nonce);
        let _tag = generic_array::GenericArray::from_slice(&tag);

        XChaCha20Poly1305::decrypt(_key, _nonce, ad, &mut plain, cipher, _tag).map_err(|_| {
            Error::CryptoError(crypto::Error::CipherError {
                alg: "XChaCha20Poly1305: Unable to seal data",
            })
        })?;

        Ok(plain)
    }

    fn random_buf(buf: &mut [u8]) -> Result<(), engine::Error> {
        fill(buf).map_err(|_| {
            // this error type might not reflect the true reason, why
            // filling some have failed. Replace with a better suited error
            // type.
            Error::CryptoError(crypto::Error::ConvertError {
                from: "Nil",
                to: "Can't generate random Bytes",
            })
        })
    }
}
