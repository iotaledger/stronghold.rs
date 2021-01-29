// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::mem::size_of;

// TODO: use generic associated types when they are available
pub trait Transferable<'a> {
    type IntoIter: Iterator<Item = &'a u8>;
    fn transfer(&'a self) -> Self::IntoIter;

    type State;
    type Out;
    fn receive<'b, I: Iterator<Item = &'b u8>>(
        st: &mut Option<Self::State>,
        bs: &mut I,
    ) -> Option<Self::Out>;
}

impl<'a> Transferable<'a> for () {
    type IntoIter = core::iter::Empty<&'a u8>;

    fn transfer(&'a self) -> Self::IntoIter {
        core::iter::empty()
    }

    type State = ();
    type Out = Self;
    fn receive<'b, I: Iterator<Item = &'b u8>>(
        _st: &mut Option<Self::State>,
        _bs: &mut I,
    ) -> Option<Self::Out> {
        Some(())
    }
}

impl<'a, A, Ao, B, Bo> Transferable<'a> for (A, B)
where A: Transferable<'a, Out = Ao>,
      Ao: Clone,
      B: Transferable<'a, Out = Bo>,
      Bo: Clone,
{
    type IntoIter = core::iter::Chain<A::IntoIter, B::IntoIter>;
    fn transfer(&'a self) -> Self::IntoIter {
        self.0.transfer().chain(self.1.transfer())
    }

    type State = (Result<Ao, Option<A::State>>, Result<Bo, Option<B::State>>);
    type Out = (Ao, Bo);
    fn receive<'b, I: Iterator<Item = &'b u8>>(
        st: &mut Option<Self::State>,
        bs: &mut I,
    ) -> Option<Self::Out> {
        let (a, b) = st.get_or_insert((Err(None), Err(None)));

        if let Err(ast) = a {
            if let Some(ao) = A::receive(ast, bs) {
                *a = Ok(ao);
            }
        }

        if a.is_ok() {
            if let Err(bst) = b {
                if let Some(bo) = B::receive(bst, bs) {
                    *b = Ok(bo);
                }
            }
        }

        match (a, b) {
            (Ok(ao), Ok(bo)) => Some((ao.clone(), bo.clone())),
            _ => None,
        }
    }
}

impl<'a, A, Ao, B, Bo, C, Co> Transferable<'a> for (A, B, C)
where A: Transferable<'a, Out = Ao>,
      Ao: Clone,
      B: Transferable<'a, Out = Bo>,
      Bo: Clone,
      C: Transferable<'a, Out = Co>,
      Co: Clone,
{
    type IntoIter = core::iter::Chain<core::iter::Chain<A::IntoIter, B::IntoIter>, C::IntoIter>;
    fn transfer(&'a self) -> Self::IntoIter {
        self.0.transfer().chain(self.1.transfer()).chain(self.2.transfer())
    }

    type State = (Result<Ao, Option<A::State>>, Result<Bo, Option<B::State>>, Result<Co, Option<C::State>>);
    type Out = (Ao, Bo, Co);
    fn receive<'b, I: Iterator<Item = &'b u8>>(
        st: &mut Option<Self::State>,
        bs: &mut I,
    ) -> Option<Self::Out> {
        let (a, b, c) = st.get_or_insert((Err(None), Err(None), Err(None)));

        if let Err(ast) = a {
            if let Some(ao) = A::receive(ast, bs) {
                *a = Ok(ao);
            }
        }

        if a.is_ok() {
            if let Err(bst) = b {
                if let Some(bo) = B::receive(bst, bs) {
                    *b = Ok(bo);
                }
            }

            if b.is_ok() {
                if let Err(cst) = c {
                    if let Some(co) = C::receive(cst, bs) {
                        *c = Ok(co);
                    }
                }
            }
        }

        match (a, b, c) {
            (Ok(ao), Ok(bo), Ok(co)) => Some((ao.clone(), bo.clone(), co.clone())),
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
            type Out = Self;
            fn receive<'b, I: Iterator<Item = &'b u8>>(
                st: &mut Option<Self::State>,
                bs: &mut I,
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
                    Some(*buf)
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
                    core::slice::from_raw_parts(self as *const _ as *const u8, size_of::<Self>()).iter()
                }
            }

            type State = (usize, [u8; size_of::<Self>()]);
            type Out = Self;
            fn receive<'b, I: Iterator<Item = &'b u8>>(
                st: &mut Option<Self::State>,
                bs: &mut I,
            ) -> Option<Self::Out> {
                let (i, buf) = st.get_or_insert((0, [0; size_of::<Self>()]));

                while *i < size_of::<Self>() {
                    if let Some(b) = bs.next() {
                        buf[*i] = *b;
                        *i += 1;
                    } else {
                        break
                    }
                }

                if *i == size_of::<Self>() {
                    Some(unsafe { *(buf as *const _ as *const Self).as_ref().unwrap() })
                } else {
                    None
                }
            }
        }
    };
}

transfer_primitive!(u8);
transfer_primitive!(u32);
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
        let r = if self.i < size_of::<usize>() {
            let p = &self.l as *const usize as *const u8;
            unsafe { p.add(self.i).as_ref() }
        } else {
            self.bs.get(self.i - size_of::<usize>())
        };
        self.i += 1;
        r
    }
}

#[cfg(feature = "stdalloc")]
impl<'a> Transferable<'a> for &[u8] {
    type IntoIter = LengthPrefix<'a>;
    fn transfer(&'a self) -> Self::IntoIter {
        LengthPrefix::new(self)
    }

    type State = (Option<usize>, std::vec::Vec<u8>);
    type Out = std::vec::Vec<u8>;
    fn receive<'b, I: Iterator<Item = &'b u8>>(
        st: &mut Option<Self::State>,
        bs: &mut I,
    ) -> Option<Self::Out> {
        let (i, buf) = st.get_or_insert((None, std::vec::Vec::with_capacity(size_of::<usize>())));

        if i.is_none() {
            while buf.len() < size_of::<usize>() {
                if let Some(b) = bs.next() {
                    buf.push(*b);
                } else {
                    break
                }
            }

            if buf.len() == size_of::<usize>() {
                let l = unsafe { *(buf.as_ptr() as *const usize).as_ref().unwrap() };
                *i = Some(l);
                *buf = std::vec::Vec::with_capacity(l);
            }
        }

        if let Some(l) = i {
            while buf.len() < *l {
                if let Some(b) = bs.next() {
                    buf.push(*b);
                } else {
                    break
                }
            }

            if buf.len() == *l {
                Some(buf.clone())
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
    use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};

    #[test]
    fn pure() {
        let mut rng = StdRng::from_entropy();

        macro_rules! pure {
            ( $t:ty ) => {
                let x = rng.gen::<$t>();
                assert_eq!(ZoneSpec::default().run(|| x), Ok(x));
            }
        }

        pure!(u8);
        pure!(u32);
        pure!(i32);
        pure!(usize);
        pure!((u32, u8));
        pure!((u32, i32, u8));

        pure!([u8; 1]);
        pure!([u8; 2]);
        pure!([u8; 4]);
        pure!([u8; 8]);
        pure!([u8; 16]);
        pure!([u8; 32]);

        pure!((u32, [u8; 32]));
        pure!((u32, [u8; 32], u8));
        pure!((u32, [u8; 8], [u8; 4]));
        pure!(([u8; 16], i32));
    }

    #[test]
    fn pure_byte_slice() {
        let mut rng = StdRng::from_entropy();

        macro_rules! pure_byte_slice {
            ( $n:tt ) => {
                let mut bs = [0u8; $n];
                rng.fill_bytes(&mut bs);
                assert_eq!(ZoneSpec::default().run(|| bs), Ok(bs));
            }
        }

        pure_byte_slice!(1);
        pure_byte_slice!(2);
        pure_byte_slice!(4);
        pure_byte_slice!(8);
        pure_byte_slice!(16);
        pure_byte_slice!(32);
        pure_byte_slice!(64);
        pure_byte_slice!(128);
        pure_byte_slice!(256);
        pure_byte_slice!(512);
        pure_byte_slice!(1024);
        pure_byte_slice!(2048);
        pure_byte_slice!(4096);
    }

    #[test]
    #[cfg(feature = "stdalloc")]
    fn pure_bytestring() {
        let bs = test_utils::fresh::bytestring();
        assert_eq!(fork(|| bs.as_slice()), Ok(bs));

        let mut rng = StdRng::from_entropy();

        let bs = test_utils::fresh::bytestring();
        let i = rng.gen::<u32>();
        assert_eq!(fork(|| (bs.as_slice(), i)), Ok((bs, i)));

        let bs = test_utils::fresh::bytestring();
        let i = rng.gen::<i32>();
        assert_eq!(fork(|| (i, bs.as_slice())), Ok((i, bs)));
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
            7
        );
        Ok(())
    }
}
