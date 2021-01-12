// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use crypto::rand;
use crypto::x25519;
use crypto::blake2b;
use crypto::ciphers::chacha::xchacha20poly1305;

pub trait Protection<A> {
    type AtRest;
}

pub trait ProtectionNew<A>: Protection<A> {
    fn protect(a: A) -> crate::Result<Self::AtRest>;
}

pub trait ProtectionNewSelf<A>: Protection<A> {
    fn protect(&self, a: A) -> crate::Result<Self::AtRest>;
}

pub trait Access<A, P: Protection<A>> {
    type Accessor;
    fn access<R: AsRef<P::AtRest>>(&self, r: R) -> crate::Result<Self::Accessor>;
}

pub trait AccessSelf<'a, A>: Protection<A> {
    type Accessor;
    fn access(&'a self) -> crate::Result<Self::Accessor>;
}

mod X25519XChaCha20Poly1305 {
    use super::*;
    use crate::mem::GuardedBox;

    #[derive(Debug)]
    pub struct Ciphertext<A> {
        // NB all we actually need is to have a byte array of the same size as A:
        // [u8; core::mem::size_of::<A>()], (this really is used as core::mem::AlwaysUninit<A>)
        bs: core::mem::MaybeUninit<A>,

        ephemeral_pk: [u8; x25519::PUBLIC_KEY_LENGTH],
        tag: [u8; xchacha20poly1305::XCHACHA20POLY1305_TAG_SIZE],
    }

    impl<A> AsRef<Ciphertext<A>> for Ciphertext<A> {
        fn as_ref(&self) -> &Self {
            &self
        }
    }

    pub struct PublicKey([u8; x25519::PUBLIC_KEY_LENGTH]);

    impl<A> Protection<A> for PublicKey {
        type AtRest = Ciphertext<A>;
    }

    impl<A> ProtectionNewSelf<A> for PublicKey {
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

            let mut bs = core::mem::MaybeUninit::uninit();
            let mut tag = [0; xchacha20poly1305::XCHACHA20POLY1305_TAG_SIZE];

            let ct: &mut [u8] = unsafe {
                core::slice::from_raw_parts_mut(bs.as_mut_ptr() as *mut u8, core::mem::size_of::<A>())
            };

            let pt: &[u8] = unsafe {
                core::slice::from_raw_parts(&a as *const _ as *const u8, core::mem::size_of::<A>())
            };

            xchacha20poly1305::encrypt(ct, &mut tag, pt, &shared, &nonce, &[])?;

            Ok(Ciphertext { bs, ephemeral_pk, tag })
        }
    }

    pub struct PrivateKey([u8; x25519::SECRET_KEY_LENGTH]);

    pub fn keypair() -> crate::Result<(PrivateKey, PublicKey)> {
        let mut s = PrivateKey([0; x25519::SECRET_KEY_LENGTH]);
        rand::fill(&mut s.0)?;
        let p = PublicKey(x25519::X25519(&s.0, None));
        Ok((s, p))
    }

    impl<A> Access<A, PublicKey> for PrivateKey {
        type Accessor = GuardedBox<A>;

        fn access<CT: AsRef<Ciphertext<A>>>(&self, ct: CT) -> crate::Result<Self::Accessor> {
            let shared = x25519::X25519(&self.0, Some(&ct.as_ref().ephemeral_pk));

            let pk = x25519::X25519(&self.0, None);

            let nonce = {
                let mut h = [0; xchacha20poly1305::XCHACHA20POLY1305_NONCE_SIZE];
                let mut i = ct.as_ref().ephemeral_pk.to_vec();
                i.extend_from_slice(&pk);
                blake2b::hash(&i, &mut h);
                h
            };

            let bs: &[u8] = unsafe {
                core::slice::from_raw_parts(ct.as_ref().bs.as_ptr() as *const u8, core::mem::size_of::<A>())
            };

            let gb: GuardedBox<A> = GuardedBox::uninit()?;
            gb.with_mut_ptr(|p| {
                let pt: &mut [u8] = unsafe {
                    core::slice::from_raw_parts_mut(p as *mut u8, core::mem::size_of::<A>())
                };

                xchacha20poly1305::decrypt(pt, bs, &shared, &ct.as_ref().tag, &nonce, &[])
            })??;

            Ok(gb)
        }
    }
}

mod AES {
    use super::*;
    use crate::mem::GuardedBox;
    use crypto::ciphers::aes::AES_256_GCM;

    #[derive(Debug)]
    pub struct Ciphertext<A> {
        // NB all we actually need is to have a byte array of the same size as A:
        // [u8; core::mem::size_of::<A>()], (this really is used as core::mem::AlwaysUninit<A>)
        bs: core::mem::MaybeUninit<A>,
        iv: [u8; AES_256_GCM::IV_LENGTH],
        tag: [u8; AES_256_GCM::TAG_LENGTH],
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

    impl<A> Protection<A> for Key {
        type AtRest = Ciphertext<A>;
    }

    impl<A> ProtectionNewSelf<A> for Key {
        fn protect(&self, a: A) -> crate::Result<Self::AtRest> {
            let mut iv = [0; AES_256_GCM::IV_LENGTH];
            rand::fill(&mut iv)?;

            let mut tag = [0; AES_256_GCM::TAG_LENGTH];

            let mut bs = core::mem::MaybeUninit::uninit();
            let ct: &mut [u8] = unsafe {
                core::slice::from_raw_parts_mut(bs.as_mut_ptr() as *mut u8, core::mem::size_of::<A>())
            };

            let pt: &[u8] = unsafe {
                core::slice::from_raw_parts(&a as *const _ as *const u8, core::mem::size_of::<A>())
            };

            AES_256_GCM::encrypt(&self.0, &iv, &[], pt, ct, &mut tag)?;

            Ok(Ciphertext { bs, iv, tag })
        }
    }

    impl<A> Access<A, Key> for Key {
        type Accessor = GuardedBox<A>;

        fn access<CT: AsRef<Ciphertext<A>>>(&self, ct: CT) -> crate::Result<Self::Accessor> {

            let bs: &[u8] = unsafe {
                core::slice::from_raw_parts(ct.as_ref().bs.as_ptr() as *const u8, core::mem::size_of::<A>())
            };

            let gb: GuardedBox<A> = GuardedBox::uninit()?;
            gb.with_mut_ptr(|p| {
                let pt: &mut [u8] = unsafe {
                    core::slice::from_raw_parts_mut(p as *mut u8, core::mem::size_of::<A>())
                };

                AES_256_GCM::decrypt(&self.0, &ct.as_ref().iv, &[], &ct.as_ref().tag, bs, pt)
            })??;

            Ok(gb)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn X25519XChaCha20Poly1305() -> crate::Result<()> {
        let (private, public) = X25519XChaCha20Poly1305::keypair()?;
        let ct = public.protect(17)?;
        let gb = private.access(&ct)?;
        assert_eq!(*gb.access()?, 17);
        Ok(())
    }

    #[test]
    fn AES() -> crate::Result<()> {
        let key = AES::Key::new()?;
        let ct = key.protect(17)?;
        let gb = key.access(&ct)?;
        assert_eq!(*gb.access()?, 17);
        Ok(())
    }
}
