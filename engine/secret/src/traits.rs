// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use runtime::guarded::{r#box::GuardedBox, string::GuardedString, vec::GuardedVec};

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
            Err(crate::Error::view("can't interpret bytestring as u32"))
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
