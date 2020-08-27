// Copyright 2020 IOTA Stiftung
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

/// all macros avoid overflow and underflow.
/// addition macro
#[macro_export]
macro_rules! add {
    ($a:expr, $b:expr) => {{
        $a.wrapping_add($b)
    }};
    ($a:expr, $b:expr, $c:expr) => {{
        $a.wrapping_add($b).wrapping_add($c)
    }};
    ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr) => {{
        $a.wrapping_add($b).wrapping_add($c).wrapping_add($d).wrapping_add($e)
    }};
}

/// subtraction macro
#[macro_export]
macro_rules! sub {
    ($a:expr, $b:expr) => {{
        $a.wrapping_sub($b)
    }};
}

/// multiplication macro
#[macro_export]
macro_rules! mult {
    ($a:expr, $b:expr) => {{
        $a.wrapping_mul($b)
    }};
}

/// bit shift right macro
#[macro_export]
macro_rules! shift_right {
    ($a:expr, $b:expr) => {{
        $a.wrapping_shr($b)
    }};
}

/// bit shift left macro
#[macro_export]
macro_rules! shift_left {
    ($a:expr, $b:expr) => {{
        $a.wrapping_shl($b)
    }};
}

/// negation macro
#[macro_export]
macro_rules! negate {
    ($a:expr) => {{
        $a.wrapping_neg()
    }};
}

/// logical or macro
#[macro_export]
macro_rules! or {
    ($a:expr, $b:expr) => {{
        $a | $b
    }};
    ($a:expr, $b:expr, $c:expr, $d:expr) => {{
        $a | $b | $c | $d
    }};
}

/// logical and macro
#[macro_export]
macro_rules! and {
    ($a:expr, $b:expr) => {{
        $a & $b
    }};
}

/// logical xor macro
#[macro_export]
macro_rules! xor {
    ($a:expr, $b:expr) => {{
        $a ^ $b
    }};
}

/// comparison macros: 1 is true and 0 is false.
/// greater than macro
#[macro_export]
macro_rules! greater_than {
    ($a:expr, $b:expr) => {{
        let c = sub!($b, $a);
        shift_right!(xor!(c, and!(xor!($a, $b), xor!($a, c))), 31)
    }};
}

/// equal to macro
#[macro_export]
macro_rules! equal {
    ($a:expr, $b:expr) => {{
        let q = xor!($a, $b);
        not_bool!(shift_right!(or!(q, negate!(q)), 31))
    }};
}

/// logical Not macro
#[macro_export]
macro_rules! not_bool {
    ($a:expr) => {{
        xor!($a, 1)
    }};
}

/// Multiplexer macro
#[macro_export]
macro_rules! mux_bool {
    ($c:expr, $x:expr, $y:expr) => {{
        xor!($y, and!(negate!($c), xor!($x, $y)))
    }};
}

/// Little Endian Decode macro
#[macro_export]
macro_rules! read32_little_endian {
    ($data:expr) => {{
        or!(
            shift_left!($data[0] as u32, 0),
            shift_left!($data[1] as u32, 8),
            shift_left!($data[2] as u32, 16),
            shift_left!($data[3] as u32, 24)
        )
    }};
}

/// Little Endian Encode macro u32
#[macro_export]
macro_rules! write32_little_endian {
    ($num:expr => $data:expr) => {{
        $data[0] = shift_right!($num, 0) as u8;
        $data[1] = shift_right!($num, 8) as u8;
        $data[2] = shift_right!($num, 16) as u8;
        $data[3] = shift_right!($num, 24) as u8;
    }};
}

/// Little Endian Encode macro u64
#[macro_export]
macro_rules! write64_little_endian {
	($num:expr => $data:expr) => ({
		write32_le!(shift_right!($num,  0) => &mut $data[0..]);
		write32_le!(shift_right!($num, 32) => &mut $data[4..]);
	});
}

/// constant time comparison macro
#[macro_export]
macro_rules! eq_const_time {
    ($a:expr, $b:expr) => {{
        use crate::{or, xor};
        if $a.len() == $b.len() {
            let mut x = 0;
            for i in 0..$a.len() {
                x = or!(x, xor!($a[i], $b[i]))
            }
            x == 0
        } else {
            false
        }
    }};
}

/// u64 to two u32s: Little Endian split macro
#[macro_export]
macro_rules! split64_little_endian {
    ($num:expr => $u32s:expr) => {{
        $u32s[0] = shift_right!($num, 0) as u32;
        $u32s[1] = shift_right!($num, 32) as u32;
    }};
}

pub mod chacha;
pub mod poly;
