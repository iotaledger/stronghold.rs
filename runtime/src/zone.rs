// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum TransferError {
    UnexpectedEOF,
    SuperfluousBytes,
}

// TODO: use generic associated types when they are available
pub trait Transferable<'a> {
    type IntoIter: Iterator<Item = &'a u8>;
    fn transfer(&'a self) -> Self::IntoIter;

    type State;
    type Out;
    fn receive<'b, I: Iterator<Item = &'b u8>>(
        st: &mut Option<Self::State>,
        bs: &mut I,
        eof: bool,
    ) -> Option<Self::Out>;
}

impl<'a> Transferable<'a> for () {
    type IntoIter = core::iter::Empty<&'a u8>;

    fn transfer(&'a self) -> Self::IntoIter {
        core::iter::empty()
    }

    type State = ();
    type Out = Result<Self, TransferError>;
    fn receive<'b, I: Iterator<Item = &'b u8>>(
        _st: &mut Option<Self::State>,
        bs: &mut I,
        _eof: bool,
    ) -> Option<Self::Out> {
        match bs.next() {
            None => Some(Ok(())),
            Some(_) => Some(Err(TransferError::SuperfluousBytes)),
        }
    }
}

impl<'a, A, Ao, B, Bo, E> Transferable<'a> for (A, B)
where A: Transferable<'a, Out = Result<Ao, E>>,
      Ao: Copy,
      B: Transferable<'a, Out = Result<Bo, E>>,
      Bo: Copy,
{
    type IntoIter = core::iter::Chain<A::IntoIter, B::IntoIter>;
    fn transfer(&'a self) -> Self::IntoIter {
        self.0.transfer().chain(self.1.transfer())
    }

    type State = (Result<Ao, Option<A::State>>, Result<Bo, Option<B::State>>);
    type Out = Result<(Ao, Bo), E>;
    fn receive<'b, I: Iterator<Item = &'b u8>>(
        st: &mut Option<Self::State>,
        bs: &mut I,
        eof: bool,
    ) -> Option<Self::Out> {
        let (a, b) = st.get_or_insert((Err(None), Err(None)));

        if let Err(ast) = a {
            match A::receive(ast, bs, eof) {
                Some(Ok(ao)) => *a = Ok(ao),
                Some(Err(e)) => return Some(Err(e)),
                None => (),
            }
        }

        if a.is_ok() {
            if let Err(bst) = b {
                match B::receive(bst, bs, eof) {
                    Some(Ok(bo)) => *b = Ok(bo),
                    Some(Err(e)) => return Some(Err(e)),
                    None => (),
                }
            }
        }

        match (a, b) {
            (Ok(ao), Ok(bo)) => Some(Ok((*ao, *bo))),
            _ => None,
        }
    }
}

impl<'a, A, Ao, B, Bo, C, Co, E> Transferable<'a> for (A, B, C)
where A: Transferable<'a, Out = Result<Ao, E>>,
      Ao: Clone,
      B: Transferable<'a, Out = Result<Bo, E>>,
      Bo: Clone,
      C: Transferable<'a, Out = Result<Co, E>>,
      Co: Clone,
{
    type IntoIter = core::iter::Chain<core::iter::Chain<A::IntoIter, B::IntoIter>, C::IntoIter>;
    fn transfer(&'a self) -> Self::IntoIter {
        self.0.transfer().chain(self.1.transfer()).chain(self.2.transfer())
    }

    type State = (Result<Ao, Option<A::State>>, Result<Bo, Option<B::State>>, Result<Co, Option<C::State>>);
    type Out = Result<(Ao, Bo, Co), E>;
    fn receive<'b, I: Iterator<Item = &'b u8>>(
        st: &mut Option<Self::State>,
        bs: &mut I,
        eof: bool,
    ) -> Option<Self::Out> {
        let (a, b, c) = st.get_or_insert((Err(None), Err(None), Err(None)));

        if let Err(ast) = a {
            match A::receive(ast, bs, eof) {
                Some(Ok(ao)) => *a = Ok(ao),
                Some(Err(e)) => return Some(Err(e)),
                None => (),
            }
        }

        if a.is_ok() {
            if let Err(bst) = b {
                match B::receive(bst, bs, eof) {
                    Some(Ok(bo)) => *b = Ok(bo),
                    Some(Err(e)) => return Some(Err(e)),
                    None => (),
                }
            }
             
            if c.is_ok() {
                if let Err(cst) = c {
                    match C::receive(cst, bs, eof) {
                        Some(Ok(co)) => *c = Ok(co),
                        Some(Err(e)) => return Some(Err(e)),
                        None => (),
                    }
                }
            }
        }

        match (a, b, c) {
            (Ok(ao), Ok(bo), Ok(co)) => Some(Ok((ao.clone(), bo.clone(), co.clone()))),
            _ => None,
        }
    }
}

macro_rules! transfer_slice_of_bytes {
    ( $n:tt ) => {
        impl<'a> Transferable<'a> for [u8; $n] {
            type IntoIter = core::slice::Iter<'a, u8>;

            fn transfer(&'a self) -> Self::IntoIter {
                self.iter()
            }

            type State = (usize, [u8; $n]);
            type Out = Result<Self, TransferError>;
            fn receive<'b, I: Iterator<Item = &'b u8>>(
                st: &mut Option<Self::State>,
                bs: &mut I,
                eof: bool,
            ) -> Option<Self::Out> {
                let (i, buf) = st.get_or_insert((0, [0; $n]));

                while *i < $n {
                    if let Some(b) = bs.next() {
                        buf[*i] = *b;
                        *i += 1;
                    } else {
                        break
                    }
                }

                if *i == $n {
                    Some(Ok(*buf))
                } else if eof {
                    Some(Err(TransferError::UnexpectedEOF))
                } else {
                    None
                }
            }
        }
    };
}

transfer_slice_of_bytes!(1);
transfer_slice_of_bytes!(2);
transfer_slice_of_bytes!(4);
transfer_slice_of_bytes!(8);
transfer_slice_of_bytes!(16);
transfer_slice_of_bytes!(32);
transfer_slice_of_bytes!(64);
transfer_slice_of_bytes!(128);
transfer_slice_of_bytes!(256);
transfer_slice_of_bytes!(512);
transfer_slice_of_bytes!(1024);
transfer_slice_of_bytes!(2048);
transfer_slice_of_bytes!(4096);

macro_rules! transfer_primitive {
    ( $t:ty ) => {
        impl<'a> Transferable<'a> for $t {
            type IntoIter = core::slice::Iter<'a, u8>;
            fn transfer(&'a self) -> Self::IntoIter {
                unsafe {
                    core::slice::from_raw_parts(self as *const _ as *const u8, core::mem::size_of::<Self>()).iter()
                }
            }

            type State = (usize, [u8; mem::size_of::<Self>()]);
            type Out = Result<Self, TransferError>;
            fn receive<'b, I: Iterator<Item = &'b u8>>(
                st: &mut Option<Self::State>,
                bs: &mut I,
                eof: bool,
            ) -> Option<Self::Out> {
                let (i, buf) = st.get_or_insert((0, [0; mem::size_of::<Self>()]));

                while *i < mem::size_of::<Self>() {
                    if let Some(b) = bs.next() {
                        buf[*i] = *b;
                        *i += 1;
                    } else {
                        break
                    }
                }

                if *i == mem::size_of::<Self>() {
                    Some(Ok(unsafe { *(buf as *const _ as *const Self).as_ref().unwrap() }))
                } else if eof {
                    Some(Err(TransferError::UnexpectedEOF))
                } else {
                    None
                }
            }
        }
    };
}

transfer_primitive!(u32);
transfer_primitive!(u8);
transfer_primitive!(i32);
transfer_primitive!(usize);

// TODO: impl<'a> Transferable<'a> for str { type Out = String }

#[cfg(feature = "stdalloc")]
pub struct LengthPrefix<'a> {
    l: usize,
    bs: &'a [u8],
    i: usize,
}

#[cfg(feature = "stdalloc")]
impl<'a> LengthPrefix<'a> {
    pub fn new(bs: &'a [u8]) -> Self {
        Self {
            l: bs.len(),
            bs,
            i: 0,
        }
    }
}

#[cfg(feature = "stdalloc")]
impl<'a> Iterator for LengthPrefix<'a> {
    type Item = &'a u8;
    fn next(&mut self) -> Option<&'a u8> {
        let r = if self.i < core::mem::size_of::<usize>() {
            let p = &self.l as *const usize as *const u8;
            unsafe { p.add(self.i).as_ref() }
        } else {
            self.bs.get(self.i - core::mem::size_of::<usize>())
        };
        self.i += 1;
        r
    }
}

#[cfg(feature = "stdalloc")]
impl<'a> Transferable<'a> for &[u8] {
    type IntoIter = LengthPrefix<'a>;
    fn transfer(&'a self) -> Self::IntoIter {
        LengthPrefix { l: self.len(), bs: self, i: 0 }
    }

    type State = (Option<usize>, std::vec::Vec<u8>);
    type Out = Result<std::vec::Vec<u8>, TransferError>;
    fn receive<'b, I: Iterator<Item = &'b u8>>(
        st: &mut Option<Self::State>,
        bs: &mut I,
        _eof: bool, // TODO: add tests for eof and superfluous bytes handling
    ) -> Option<Self::Out> {
        let (i, buf) = st.get_or_insert((None, std::vec::Vec::with_capacity(mem::size_of::<usize>())));
        buf.extend(bs);

        if i.is_none() {
            if buf.len() >= mem::size_of::<usize>() {
                *i = Some(unsafe { *(buf[..mem::size_of::<usize>()].as_ptr() as *const usize).as_ref().unwrap() });
                *buf = buf.split_off(mem::size_of::<usize>());
            }
        }

        if let Some(l) = i {
            if buf.capacity() < *l {
                buf.reserve(*l - buf.capacity());
            }
            if buf.len() == *l {
                Some(Ok(buf.clone()))
            } else {
                None
            }
        } else {
            None
        }
    }
}

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
        assert_eq!(ZoneSpec::default().run(|| 7u8)?, Ok(7u8));
        assert_eq!(ZoneSpec::default().run(|| 7u32)?, Ok(7u32));
        assert_eq!(ZoneSpec::default().run(|| -7i32)?, Ok(-7i32));
        assert_eq!(ZoneSpec::default().run(|| (7u32, 9usize))?, Ok((7u32, 9usize)));
        Ok(())
    }

    #[test]
    fn pure_buffer() -> crate::Result<()> {
        let mut bs = [0u8; 256];
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

                let b = Box::new(7u32);
                *b
            })?,
            Ok(7)
        );
        Ok(())
    }
}
