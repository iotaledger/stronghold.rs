// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crypto::{ciphers::aes::AES_256_GCM, rand};

use crate::{Access, Protectable, Protection};

use std::marker::PhantomData;

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

#[cfg(test)]
mod tests {
    use super::*;
    use test_utils::fresh;

    #[test]
    fn int() -> crate::Result<()> {
        let key = Key::new()?;
        let ct = key.protect(17)?;
        let gb = key.access(&ct)?;
        assert_eq!(*gb.access(), 17);
        Ok(())
    }

    #[test]
    fn bytestring() -> crate::Result<()> {
        let key = Key::new()?;
        let pt = fresh::bytestring();
        let ct = key.protect(pt.as_slice())?;
        let gv = key.access(&ct)?;
        assert_eq!(&*gv.access(), pt);
        Ok(())
    }

    #[test]
    fn string() -> crate::Result<()> {
        let key = Key::new()?;
        let s = fresh::string();
        let ct = key.protect(s.as_str())?;
        let gs = key.access(&ct)?;
        assert_eq!(&*gs.access(), s);
        Ok(())
    }
}
