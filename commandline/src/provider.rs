use crypto::XChaChaPoly;
use random::{
    primitives::{cipher::AeadCipher, rng::SecureRng},
    OsRng,
};

use serde::{Deserialize, Serialize};
use vault::{BoxProvider, Key};

#[derive(Deserialize, Serialize, Debug)]
pub struct Provider;
// add Nonce and Tag len to the provider.
impl Provider {
    const NONCE_LEN: usize = 24;
    const TAG_LEN: usize = 16;
}

// implement the BoxProvider trait.
impl BoxProvider for Provider {
    // setup the box key length.
    fn box_key_len() -> usize {
        32
    }

    // setup the box overhead length.
    fn box_overhead() -> usize {
        Self::NONCE_LEN + Self::TAG_LEN
    }

    // seal a box with the key.  Append the nonce to the data after encryption
    fn box_seal(key: &Key<Self>, ad: &[u8], data: &[u8]) -> vault::Result<Vec<u8>> {
        let mut boxx = vec![0; data.len() + Self::box_overhead()];
        let (nonce, cipher) = boxx.split_at_mut(Self::NONCE_LEN);
        Self::random_buf(nonce)?;

        XChaChaPoly
            .seal_with(cipher, data, ad, key.bytes(), nonce)
            .map_err(|_| vault::Error::CryptoError(String::from("Unable to seal data")))?;
        Ok(boxx)
    }

    // open the box with the key.
    fn box_open(key: &Key<Self>, ad: &[u8], data: &[u8]) -> vault::Result<Vec<u8>> {
        let mut plain = match data.len() {
            len if len >= Self::box_overhead() => vec![0; len - Self::box_overhead()],
            _ => Err(vault::Error::CryptoError(String::from("Truncated cipher")))?,
        };

        let (nonce, cipher) = data.split_at(Self::NONCE_LEN);

        XChaChaPoly
            .open_to(&mut plain, cipher, ad, key.bytes(), nonce)
            .map_err(|_| vault::Error::CryptoError(String::from("Invalid Cipher")))?;

        Ok(plain)
    }

    // create a random buffer
    fn random_buf(buf: &mut [u8]) -> vault::Result<()> {
        OsRng
            .random(buf)
            .map_err(|_| vault::Error::CryptoError(String::from("Can't generated random Bytes")))
    }
}
