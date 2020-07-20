use crate::internal::poly::{poly1305_finish, poly1305_init, poly1305_update};

use primitives::{
    auth::{MessageAuthCode, MessageAuthCodeInfo},
    rng::{SecretKeyGen, SecureRng},
};

use std::error::Error;

// Size of the Key
pub const POLY1305_KEY: usize = 32;
// Size of the auth tag
pub const POLY1305_TAG: usize = 16;

pub struct Poly1305;

impl Poly1305 {
    // creates a MAC
    pub fn message_auth_code() -> Box<dyn MessageAuthCode> {
        Box::new(Self)
    }

    // function to create ChaChaPoly-IETF AEAD
    pub(in crate) fn chachapoly_auth(
        tag: &mut [u8],
        ad: &[u8],
        data: &[u8],
        foot: &[u8],
        key: &[u8],
    ) {
        let (mut r, mut s, mut u, mut a) = (vec![0; 5], vec![0; 4], vec![0; 5], vec![0; 5]);
        poly1305_init(&mut r, &mut s, &mut u, key);

        poly1305_update(&mut a, &r, &u, ad, false);
        poly1305_update(&mut a, &r, &u, data, false);
        poly1305_update(&mut a, &r, &u, foot, true);
        poly1305_finish(tag, &mut a, &s);
    }
}

impl SecretKeyGen for Poly1305 {
    fn new_secret_key(
        &self,
        buf: &mut [u8],
        rng: &mut dyn SecureRng,
    ) -> Result<usize, Box<dyn Error + 'static>> {
        verify_keygen!(POLY1305_KEY => buf);

        rng.random(&mut buf[..POLY1305_KEY])?;
        Ok(POLY1305_KEY)
    }
}

impl MessageAuthCode for Poly1305 {
    fn info(&self) -> MessageAuthCodeInfo {
        MessageAuthCodeInfo {
            id: "Poly1305",
            one_time: true,
            len: POLY1305_TAG,
            mac_lens: POLY1305_TAG..POLY1305_TAG,
            key_lens: POLY1305_KEY..POLY1305_KEY,
        }
    }

    fn auth(
        &self,
        buf: &mut [u8],
        data: &[u8],
        key: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>> {
        verify_auth!(key => [POLY1305_KEY], => [buf, POLY1305_TAG]);

        let (mut r, mut s, mut u, mut a) = (vec![0; 5], vec![0; 4], vec![0; 5], vec![0; 5]);
        poly1305_init(&mut r, &mut s, &mut u, key);
        poly1305_update(&mut a, &r, &u, data, true);
        poly1305_finish(buf, &mut a, &s);

        Ok(POLY1305_TAG)
    }
}
