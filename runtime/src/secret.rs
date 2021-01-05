// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

trait Protection<A> {
    type AtRest;
}

trait ProtectionNew<A>: Protection<A> {
    fn protect(a: A) -> Self::AtRest;
}

trait ProtectionNewSelf<A>: Protection<A> {
    fn protect(&self, a: A) -> Self::AtRest;
}

trait Access<A, P: Protection<A>> {
    type Accessor;
    fn access<R: AsRef<P::AtRest>>(&self, r: R) -> Self::Accessor;
}

trait AccessSelf<A>: Protection<A> {
    type Accessor;
    fn access(&self) -> Self::Accessor;
}


struct GuardedBox<A> {
    alloc: crate::mem::GuardedAllocation,
    a: core::marker::PhantomData<A>,
}

struct GuardedBoxAccess<A> {
    a: core::marker::PhantomData<A>,
}

impl<A> GuardedBoxAccess<A> {
    fn get(&self) -> &A {
        unimplemented!()
    }
}

impl<A> Protection<A> for GuardedBox<A> {
    type AtRest = Self;
}

impl<A> ProtectionNew<A> for GuardedBox<A> {
    fn protect(_a: A) -> Self::AtRest {
        unimplemented!()
    }
}

impl<A> AccessSelf<A> for GuardedBox<A> {
    type Accessor = GuardedBoxAccess<A>;

    fn access(&self) -> Self::Accessor {
        unimplemented!()
    }
}


mod X25519XChaCha20Poly1305 {
    use super::*;

    pub struct Ciphertext<A> {
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
        fn protect(&self, _a: A) -> Self::AtRest {
            unimplemented!()
        }
    }

    pub struct PrivateKey {}

    impl<A> Access<A, PublicKey> for PrivateKey {
        type Accessor = GuardedBox<A>;

        fn access<CT: AsRef<Ciphertext<A>>>(&self, _ct: CT) -> Self::Accessor {
            unimplemented!()
        }
    }
}


mod AES {
    use super::*;

    pub struct Ciphertext<A> {
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
        fn protect(&self, _a: A) -> Self::AtRest {
            unimplemented!()
        }
    }

    impl<A> Access<A, Key> for Key {
        type Accessor = GuardedBox<A>;

        fn access<CT: AsRef<Ciphertext<A>>>(&self, _ct: CT) -> Self::Accessor {
            unimplemented!()
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "unimplemented"]
    fn go() {
        let gb = GuardedBox::protect(7);
        assert_eq!(*gb.access().get(), 7);

        let public = X25519XChaCha20Poly1305::PublicKey {};
        let private = X25519XChaCha20Poly1305::PrivateKey {};
        let ct = public.protect(17);
        let gb = private.access(&ct);
        assert_eq!(*gb.access().get(), 17);
    }
}
