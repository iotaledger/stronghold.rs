// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub enum TransferableState<T, Error> {
    Continue,
    Done(T),
    Err(Error),
}

// TODO: split 'a into input and output lifetimes
// TODO: use generic associated types when they are available
pub trait Transferable<'a>: Sized {
    type IntoIter: Iterator<Item = &'a u8>;
    fn to_iter(&'a self) -> Self::IntoIter;

    type Error;
    type State;
    type Out;
    fn from_iter<I: Iterator<Item = &'a u8>>(st: &mut Option<Self::State>, _bs: I) -> TransferableState<Self::Out, Self::Error>;
}

impl<'a> Transferable<'a> for () {
    type IntoIter = core::iter::Empty<&'a u8>;

    fn to_iter(&'a self) -> Self::IntoIter {
        core::iter::empty()
    }

    type Error = (); // TODO: use ! when it becomes stable
    type State = (); // TODO: use ! when it becomes stable
    type Out = Self;
    fn from_iter<I: Iterator<Item = &'a u8>>(_st: &mut Option<Self::State>, _bs: I) ->  TransferableState<Self::Out, Self::Error> {
        TransferableState::Done(())
    }
}

impl<'a> Transferable<'a> for [u8; 128] {
    type IntoIter = core::slice::Iter<'a, u8>;

    fn to_iter(&'a self) -> Self::IntoIter {
        self.iter()
    }

    type Error = ();
    type State = [u8; 128];
    type Out = Self;
    fn from_iter<I: Iterator<Item = &'a u8>>(st: &mut Option<Self::State>, _bs: I) ->  TransferableState<Self::Out, Self::Error> {
        let bs = st.get_or_insert([0; 128]);
        TransferableState::Done(*bs)
    }
}

impl<'a> Transferable<'a> for u32 {
    type IntoIter = core::slice::Iter<'a, u8>;
    fn to_iter(&'a self) -> Self::IntoIter {
        todo!()
    }

    type Error = ();
    type State = [u8; mem::size_of::<Self>()];
    type Out = Self;
    fn from_iter<I: Iterator<Item = &'a u8>>(st: &mut Option<Self::State>, _bs: I) ->  TransferableState<Self::Out, Self::Error> {
        todo!()
    }
}

// TODO: impl<'a> Transferable<'a> for str { type Out = String }
// TODO: impl<'a> Transferable<'a> for [u8] { type Out = Vec<u8>; }

#[cfg(unix)]
include!("zone_posix.rs");

#[cfg(target_os = "linux")]
include!("zone_linux.rs");

#[cfg(target_os = "macos")]
include!("zone_macos.rs");

#[cfg(windows)]
include!("zone_windows.rs");

#[cfg(test)]
mod common_tests {
    use super::*;
    use rand::{rngs::OsRng, RngCore};

    #[test]
    fn pure() -> crate::Result<()> {
        assert_eq!(ZoneSpec::default().run(|| 7)?, Ok(7));
        Ok(())
    }

    #[test]
    fn pure_buffer() -> crate::Result<()> {
        let mut bs = [0u8; 128];
        OsRng.fill_bytes(&mut bs);
        assert_eq!(ZoneSpec::default().run(|| bs)?, Ok(bs));
        Ok(())
    }

    #[test]
    fn heap() -> crate::Result<()> {
        assert_eq!(
            ZoneSpec::default().secure_memory().run(|| {
                extern crate alloc;
                use alloc::boxed::Box;

                let b = Box::new(7);
                *b
            })?,
            Ok(7)
        );
        Ok(())
    }
}
