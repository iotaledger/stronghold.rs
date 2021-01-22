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
    fn transfer(&'a self) -> Self::IntoIter;

    type Error;
    type State;
    type Out;
    fn receive<'b, I: Iterator<Item = &'b u8>>(
        st: &mut Option<Self::State>,
        _bs: I,
    ) -> TransferableState<Self::Out, Self::Error>;
}

impl<'a> Transferable<'a> for () {
    type IntoIter = core::iter::Empty<&'a u8>;

    fn transfer(&'a self) -> Self::IntoIter {
        core::iter::empty()
    }

    type Error = (); // TODO: use ! when it becomes stable
    type State = (); // TODO: use ! when it becomes stable
    type Out = Self;
    fn receive<'b, I: Iterator<Item = &'b u8>>(
        _st: &mut Option<Self::State>,
        _bs: I,
    ) -> TransferableState<Self::Out, Self::Error> {
        TransferableState::Done(())
    }
}

impl<'a> Transferable<'a> for [u8; 128] {
    type IntoIter = core::slice::Iter<'a, u8>;

    fn transfer(&'a self) -> Self::IntoIter {
        self.iter()
    }

    type Error = ();
    type State = (usize, [u8; 128]);
    type Out = Self;
    fn receive<'b, I: Iterator<Item = &'b u8>>(
        st: &mut Option<Self::State>,
        bs: I,
    ) -> TransferableState<Self::Out, Self::Error> {
        let (i, buf) = st.get_or_insert((0, [0; 128]));
        for b in bs {
            buf[*i] = *b;
            *i += 1;
        }

        if *i == mem::size_of::<Self>() {
            TransferableState::Done(*buf)
        } else {
            TransferableState::Continue
        }
    }
}

impl<'a> Transferable<'a> for u32 {
    type IntoIter = core::slice::Iter<'a, u8>;
    fn transfer(&'a self) -> Self::IntoIter {
        unsafe { core::slice::from_raw_parts(self as *const _ as *const u8, core::mem::size_of::<Self>()).iter() }
    }

    type Error = ();
    type State = (usize, [u8; mem::size_of::<Self>()]);
    type Out = Self;
    fn receive<'b, I: Iterator<Item = &'b u8>>(
        st: &mut Option<Self::State>,
        bs: I,
    ) -> TransferableState<Self::Out, Self::Error> {
        let (i, buf) = st.get_or_insert((0, [0; mem::size_of::<Self>()]));
        for b in bs {
            buf[*i] = *b;
            *i += 1;
        }

        if *i == mem::size_of::<Self>() {
            TransferableState::Done(unsafe { *(buf as *const _ as *const Self).as_ref().unwrap() })
        } else {
            TransferableState::Continue
        }
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
