// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

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

    #[derive(Debug,Clone,Copy)]
    pub struct Ciphertext<A> {
        // NB all we actually need is to have a byte array of the same size as A:
        // [u8; core::mem::size_of::<A>()], (this really is used as core::mem::AlwaysUninit<A>)
        bs: core::mem::MaybeUninit<A>,
    }

    impl<A> AsRef<Ciphertext<A>> for Ciphertext<A> {
        fn as_ref(&self) -> &Self {
            &self
        }
    }

    pub struct PublicKey {}

    impl<A> Protection<A> for PublicKey {
        type AtRest = Ciphertext<A>;
    }

    impl<A> ProtectionNewSelf<A> for PublicKey {
        fn protect(&self, _a: A) -> crate::Result<Self::AtRest> {
            unimplemented!()
        }
    }

    pub struct PrivateKey {}

    impl<A> Access<A, PublicKey> for PrivateKey {
        type Accessor = GuardedBox<A>;

        fn access<CT: AsRef<Ciphertext<A>>>(&self, _ct: CT) -> crate::Result<Self::Accessor> {
            unimplemented!()
        }
    }
}

mod AES {
    use super::*;
    use crate::mem::GuardedBox;

    #[derive(Debug,Clone,Copy)]
    pub struct Ciphertext<A> {
        // NB all we actually need is to have a byte array of the same size as A:
        // [u8; core::mem::size_of::<A>()], (this really is used as core::mem::AlwaysUninit<A>)
        bs: core::mem::MaybeUninit<A>,
    }

    impl<A> AsRef<Ciphertext<A>> for Ciphertext<A> {
        fn as_ref(&self) -> &Self {
            &self
        }
    }

    pub struct Key {}

    impl<A> Protection<A> for Key {
        type AtRest = Ciphertext<A>;
    }

    impl<A> ProtectionNewSelf<A> for Key {
        fn protect(&self, _a: A) -> crate::Result<Self::AtRest> {
            unimplemented!()
        }
    }

    impl<A> Access<A, Key> for Key {
        type Accessor = GuardedBox<A>;

        fn access<CT: AsRef<Ciphertext<A>>>(&self, _ct: CT) -> crate::Result<Self::Accessor> {
            unimplemented!()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "unimplemented"]
    fn go() -> crate::Result<()> {
        let public = X25519XChaCha20Poly1305::PublicKey {};
        let private = X25519XChaCha20Poly1305::PrivateKey {};
        let ct = public.protect(17)?;
        let gb = private.access(&ct)?;
        assert_eq!(*gb.access()?, 17);
        Ok(())
    }
}
