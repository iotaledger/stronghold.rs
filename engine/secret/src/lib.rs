// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use runtime::guarded::{r#box::GuardedBox, string::GuardedString, vec::GuardedVec};

use std::marker::PhantomData;

#[derive(Debug, PartialEq)]
pub enum Error {
    ViewError { reason: &'static str },
    RuntimeError(runtime::Error),
    CryptoError(crypto::Error),
}

type Result<A> = std::result::Result<A, Error>;

impl Error {
    fn view(reason: &'static str) -> Error {
        Error::ViewError { reason }
    }
}

impl From<runtime::Error> for Error {
    fn from(e: runtime::Error) -> Self {
        Error::RuntimeError(e)
    }
}

impl From<crypto::Error> for Error {
    fn from(e: crypto::Error) -> Self {
        Error::CryptoError(e)
    }
}

pub trait Protectable {
    fn into_plaintext(&self) -> &[u8];

    type Accessor;
    fn view_plaintext(bs: &[u8]) -> crate::Result<Self::Accessor>;
}

pub trait Protection<A: Protectable> {
    type AtRest;
    fn protect(&self, a: A) -> crate::Result<Self::AtRest>;
}

pub trait Access<A: Protectable, P: Protection<A>> {
    fn access<R: AsRef<P::AtRest>>(&self, r: R) -> crate::Result<A::Accessor>;
}

impl Protectable for u32 {
    fn into_plaintext(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const _ as *const u8, core::mem::size_of::<Self>()) }
    }

    type Accessor = GuardedBox<u32>;
    fn view_plaintext(bs: &[u8]) -> crate::Result<Self::Accessor> {
        if bs.len() == core::mem::size_of::<Self>() {
            let x = bs as *const _ as *const Self;
            GuardedBox::new(unsafe { *x.as_ref().unwrap() }).map_err(|e| e.into())
        } else {
            Err(Error::view("can't interpret bytestring as u32"))
        }
    }
}

impl Protectable for &[u8] {
    fn into_plaintext(&self) -> &[u8] {
        self
    }

    type Accessor = GuardedVec<u8>;
    fn view_plaintext(bs: &[u8]) -> crate::Result<Self::Accessor> {
        GuardedVec::copy(bs).map_err(|e| e.into())
    }
}

impl Protectable for &str {
    fn into_plaintext(&self) -> &[u8] {
        self.as_bytes()
    }

    type Accessor = GuardedString;
    fn view_plaintext(bs: &[u8]) -> crate::Result<Self::Accessor> {
        GuardedString::new(unsafe { core::str::from_utf8_unchecked(bs) }).map_err(|e| e.into())
    }
}

pub mod X25519XChaCha20Poly1305 {
    use super::*;
    use crypto::{blake2b, ciphers::chacha::xchacha20poly1305, rand, x25519};

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

    #[test]
    fn int() -> crate::Result<()> {
        let (private, public) = X25519XChaCha20Poly1305::keypair()?;
        let ct = public.protect(17)?;
        let gb = private.access(&ct)?;
        assert_eq!(*gb.access(), 17);
        Ok(())
    }

    #[test]
    fn bytestring() -> crate::Result<()> {
        let (private, public) = X25519XChaCha20Poly1305::keypair()?;
        let pt: &[u8] = &[0, 1, 2];
        let ct = public.protect(pt)?;
        let gv = private.access(&ct)?;
        assert_eq!(&*gv.access(), pt);
        Ok(())
    }

    #[test]
    fn string() -> crate::Result<()> {
        let (private, public) = X25519XChaCha20Poly1305::keypair()?;
        let ct = public.protect("foo")?;
        let gs = private.access(&ct)?;
        assert_eq!(&*gs.access(), "foo");
        Ok(())
    }
}

pub mod AES {
    use super::*;
    use crypto::{ciphers::aes::AES_256_GCM, rand};

    #[derive(Debug)]
    pub struct Ciphertext<A> {
        ct: Vec<u8>,
        iv: [u8; AES_256_GCM::IV_LENGTH],
        tag: [u8; AES_256_GCM::TAG_LENGTH],
        a: PhantomData<A>,
    }

    impl<A> AsRef<Ciphertext<A>> for Ciphertext<A> {
        fn as_ref(&self) -> &Self {
            &self
        }
    }

    pub struct Key([u8; AES_256_GCM::KEY_LENGTH]);

    impl Key {
        pub fn new() -> crate::Result<Self> {
            let mut bs = [0; AES_256_GCM::KEY_LENGTH];
            rand::fill(&mut bs)?;
            Ok(Key(bs))
        }
    }

    impl<A: Protectable> Protection<A> for Key {
        type AtRest = Ciphertext<A>;

        fn protect(&self, a: A) -> crate::Result<Self::AtRest> {
            let mut iv = [0; AES_256_GCM::IV_LENGTH];
            rand::fill(&mut iv)?;

            let mut tag = [0; AES_256_GCM::TAG_LENGTH];

            let pt = a.into_plaintext();
            let mut ct = vec![0; pt.len()];
            AES_256_GCM::encrypt(&self.0, &iv, &[], &pt, &mut ct, &mut tag)?;

            Ok(Ciphertext {
                ct,
                iv,
                tag,
                a: PhantomData,
            })
        }
    }

    impl<A: Protectable> Access<A, Key> for Key {
        fn access<CT: AsRef<Ciphertext<A>>>(&self, ct: CT) -> crate::Result<A::Accessor> {
            let mut pt = vec![0; ct.as_ref().ct.len()];
            AES_256_GCM::decrypt(
                &self.0,
                &ct.as_ref().iv,
                &[],
                &ct.as_ref().tag,
                &ct.as_ref().ct,
                &mut pt,
            )?;

            A::view_plaintext(&pt)
        }
    }

    #[test]
    fn int() -> crate::Result<()> {
        let key = AES::Key::new()?;
        let ct = key.protect(17)?;
        let gb = key.access(&ct)?;
        assert_eq!(*gb.access(), 17);
        Ok(())
    }

    #[test]
    fn bytestring() -> crate::Result<()> {
        let key = AES::Key::new()?;
        let pt: &[u8] = &[0, 1, 2];
        let ct = key.protect(pt)?;
        let gv = key.access(&ct)?;
        assert_eq!(&*gv.access(), pt);
        Ok(())
    }

    #[test]
    fn string() -> crate::Result<()> {
        let key = AES::Key::new()?;
        let ct = key.protect("foo")?;
        let gs = key.access(&ct)?;
        assert_eq!(&*gs.access(), "foo");
        Ok(())
    }
}
