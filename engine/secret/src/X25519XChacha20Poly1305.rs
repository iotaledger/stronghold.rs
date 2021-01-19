// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crypto::{blake2b, ciphers::chacha::xchacha20poly1305, rand, x25519};

use crate::{Access, Protectable, Protection};

use std::marker::PhantomData;

#[derive(Debug)]
pub struct Ciphertext<A> {
    ct: Vec<u8>,
    ephemeral_pk: [u8; x25519::PUBLIC_KEY_LENGTH],
    tag: [u8; xchacha20poly1305::XCHACHA20POLY1305_TAG_SIZE],
    a: PhantomData<A>,
}

impl<A> AsRef<Ciphertext<A>> for Ciphertext<A> {
    fn as_ref(&self) -> &Self {
        &self
    }
}

pub struct PublicKey([u8; x25519::PUBLIC_KEY_LENGTH]);

impl<A: Protectable> Protection<A> for PublicKey {
    type AtRest = Ciphertext<A>;

    fn protect(&self, a: A) -> crate::Result<Self::AtRest> {
        let (PrivateKey(ephemeral_key), PublicKey(ephemeral_pk)) = keypair()?;

        let shared = x25519::X25519(&ephemeral_key, Some(&self.0));

        let nonce = {
            let mut h = [0; xchacha20poly1305::XCHACHA20POLY1305_NONCE_SIZE];
            let mut i = ephemeral_pk.to_vec();
            i.extend_from_slice(&self.0);
            blake2b::hash(&i, &mut h);
            h
        };

        let mut tag = [0; xchacha20poly1305::XCHACHA20POLY1305_TAG_SIZE];

        let pt = a.into_plaintext();
        let mut ct = vec![0; pt.len()];
        xchacha20poly1305::encrypt(&mut ct, &mut tag, &pt, &shared, &nonce, &[])?;

        Ok(Ciphertext {
            ct,
            ephemeral_pk,
            tag,
            a: PhantomData,
        })
    }
}

pub struct PrivateKey([u8; x25519::SECRET_KEY_LENGTH]);

pub fn keypair() -> crate::Result<(PrivateKey, PublicKey)> {
    let mut s = PrivateKey([0; x25519::SECRET_KEY_LENGTH]);
    rand::fill(&mut s.0)?;
    let p = PublicKey(x25519::X25519(&s.0, None));
    Ok((s, p))
}

impl<A: Protectable> Access<A, PublicKey> for PrivateKey {
    fn access<CT: AsRef<Ciphertext<A>>>(&self, ct: CT) -> crate::Result<A::Accessor> {
        let shared = x25519::X25519(&self.0, Some(&ct.as_ref().ephemeral_pk));

        let pk = x25519::X25519(&self.0, None);

        let nonce = {
            let mut h = [0; xchacha20poly1305::XCHACHA20POLY1305_NONCE_SIZE];
            let mut i = ct.as_ref().ephemeral_pk.to_vec();
            i.extend_from_slice(&pk);
            blake2b::hash(&i, &mut h);
            h
        };

        let mut pt = vec![0; ct.as_ref().ct.len()];
        xchacha20poly1305::decrypt(&mut pt, &ct.as_ref().ct, &shared, &ct.as_ref().tag, &nonce, &[])?;

        A::view_plaintext(&pt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_utils::fresh;

    #[test]
    fn int() -> crate::Result<()> {
        let (private, public) = keypair()?;
        let ct = public.protect(17)?;
        let gb = private.access(&ct)?;
        assert_eq!(*gb.access(), 17);
        Ok(())
    }

    #[test]
    fn bytestring() -> crate::Result<()> {
        let (private, public) = keypair()?;
        let pt = fresh::bytestring();
        let ct = public.protect(pt.as_slice())?;
        let gv = private.access(&ct)?;
        assert_eq!(&*gv.access(), pt);
        Ok(())
    }

    #[test]
    fn string() -> crate::Result<()> {
        let (private, public) = keypair()?;
        let s = fresh::string();
        let ct = public.protect(s.as_str())?;
        let gs = private.access(&ct)?;
        assert_eq!(&*gs.access(), s);
        Ok(())
    }
}
