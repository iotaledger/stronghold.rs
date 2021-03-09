// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod bytes;
mod const_eq;
mod rand;
mod zero;

pub use bytes::{Bytes, ContiguousBytes};
pub use const_eq::ConstEq;
pub use rand::Randomized;
pub use zero::Zeroed;

macro_rules! impls {
    ($($ty:ty),* ; $ns:tt) => {$(
        impls!{prim  $ty}
        impls!{array $ty; $ns}
    )*};

    (prim $ty:ty) => {
        unsafe impl Bytes for $ty {}
    };

    (array $ty:ty; ($($n:tt)*)) => {$(
        #[allow(trivial_casts)]
        unsafe impl Bytes for [$ty; $n] {}
    )*};
}

impls! {
    (),
    u8, u16, u32, u64, u128; (
    0  1  2  3  4  5  6  7  8  9
    10 11 12 13 14 15 16 17 18 19
    20 21 22 23 24 25 26 27 28 29
    30 31 32 33 34 35 36 37 38 39
    40 41 42 43 44 45 46 47 48 49
    50 51 52 53 54 55 56 57 58 59
    60 61 62 63 64 66 67 68 69 70
    71 72 73 74 75 76 77 78 79 80
    128 256 384 512 1024 2048 4096 8192
)}
