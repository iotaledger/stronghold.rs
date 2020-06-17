#[macro_export]
macro_rules! add {
    ($a:expr, $b:expr) => {{
        $a.wrapping_add($b)
    }};
    ($a:expr, $b:expr, $c:expr) => {{
        $a.wrapping_add($b).wrapping_add($c)
    }};
    ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr) => {{
        $a.wrapping_add($b)
            .wrapping_add($c)
            .wrapping_add($d)
            .wrapping_add($e)
    }};
}

#[macro_export]
macro_rules! sub {
    ($a:expr, $b:expr) => {{
        $a.wrapping_sub($b)
    }};
}

#[macro_export]
macro_rules! mult {
    ($a:expr, $b:expr) => {{
        $a.wrapping_mul($b)
    }};
}

#[macro_export]
macro_rules! shift_right {
    ($a:expr, $b:expr) => {{
        $a.wrapping_shr($b)
    }};
}

#[macro_export]
macro_rules! shift_left {
    ($a:expr, $b:expr) => {{
        $a.wrapping_shl($b)
    }};
}

#[macro_export]
macro_rules! negate {
    ($a:expr) => {{
        $a.wrapping_neg()
    }};
}

#[macro_export]
macro_rules! and {
    ($a:expr, $b:expr) => {{
        $a & $b
    }};
}

#[macro_export]
macro_rules! or {
    ($a:expr, $b:expr) => {{
        $a | $b
    }};
    ($a:expr, $b:expr, $c:expr, $d:expr) => {{
        $a | $b | $c | $d
    }};
}

#[macro_export]
macro_rules! xor {
    ($a:expr, $b:expr) => {{
        $a ^ $b
    }};
}

#[macro_export]
macro_rules! greater_than {
    ($a:expr, $b:expr) => {{
        let c = sub!($b, $a);
        shr!(xor!(c, and!(xor!($a, $b), xor!($a, c))), 31)
    }};
}

#[macro_export]
macro_rules! equal {
    ($a:expr, $b:expr) => {{
        let q = xor!($a, $b);
        not_bool!(shr!(or!(q, neg!(q)), 31))
    }};
}

#[macro_export]
macro_rules! not_bool {
    ($a:expr) => {{
        xor!($a, 1)
    }};
}

#[macro_export]
macro_rules! mux_bool {
    ($c:expr, $x:expr, $y:expr) => {{
        xor!($y, and!(neg!($c), xor!($x, $y)))
    }};
}

#[macro_export]
macro_rules! read32_little_edian {
    ($data:expr) => {{
        or!(
            shl!($data[0] as u32, 0),
            shl!($data[1] as u32, 8),
            shl!($data[2] as u32, 16),
            shl!($data[3] as u32, 24)
        )
    }};
}

#[macro_export]
macro_rules! write32_little_edian {
    ($num:expr => $data:expr) => {{
        $data[0] = shr!($num, 0) as u8;
        $data[1] = shr!($num, 8) as u8;
        $data[2] = shr!($num, 16) as u8;
        $data[3] = shr!($num, 24) as u8;
    }};
}

#[macro_export]
macro_rules! write64_little_edian {
	($num:expr => $data:expr) => ({
		write32_le!(shr!($num,  0) => &mut $data[0..]);
		write32_le!(shr!($num, 32) => &mut $data[4..]);
	});
}

#[macro_export]
macro_rules! split64_little_edian {
    ($num:expr => $u32s:expr) => {{
        $u32s[0] = shr!($num, 0) as u32;
        $u32s[1] = shr!($num, 32) as u32;
    }};
}

#[macro_export]
macro_rules! eq_const_time {
    ($a:expr, $b:expr) => {{
        match $a.len() == $b.len() {
            true => {
                let mut x = 0;
                for i in 0..$a.len() {
                    x = or!(x, xor!($a[i], $b[i]))
                }
                x == 0
            }
            false => false,
        }
    }};
}

pub mod chacha;
pub mod poly;
