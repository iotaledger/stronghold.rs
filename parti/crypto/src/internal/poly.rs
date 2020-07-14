use std::cmp::min;

// loads a key into r and s and computes the key multipliers
pub fn poly1305_init(r: &mut [u32], s: &mut [u32], mu: &mut [u32], key: &[u8]) {
    // load key
    r[0] = and!(
        shift_right!(read32_little_endian!(&key[0..]), 0),
        0x03FFFFFF
    );
    r[1] = and!(
        shift_right!(read32_little_endian!(&key[3..]), 2),
        0x03FFFF03
    );
    r[2] = and!(
        shift_right!(read32_little_endian!(&key[6..]), 4),
        0x03FFC0FF
    );
    r[3] = and!(
        shift_right!(read32_little_endian!(&key[9..]), 6),
        0x03F03FFF
    );
    r[4] = and!(
        shift_right!(read32_little_endian!(&key[12..]), 8),
        0x000FFFFF
    );

    s[0] = read32_little_endian!(&key[16..]);
    s[1] = read32_little_endian!(&key[20..]);
    s[2] = read32_little_endian!(&key[24..]);
    s[3] = read32_little_endian!(&key[28..]);

    // compute multipliers
    mu[0] = 0;
    mu[1] = mult!(r[1], 5);
    mu[2] = mult!(r[2], 5);
    mu[3] = mult!(r[3], 5);
    mu[4] = mult!(r[4], 5);
}

// updates the value a with any data using the key and the multipliers
// pads any incomplete block with 0 bytes.
pub fn poly1305_update(a: &mut [u32], r: &[u32], mu: &[u32], mut data: &[u8], is_last: bool) {
    let mut buf = vec![0; 16];
    let mut w = vec![0; 5];

    // process data
    while !data.is_empty() {
        // put data into buffer and append 0x01 byte as padding as needed
        let buf_len = min(data.len(), buf.len());
        if buf_len < 16 {
            buf.copy_from_slice(&[0; 16]);
            if is_last {
                buf[buf_len] = 0x01
            }
        }
        buf[..buf_len].copy_from_slice(&data[..buf_len]);

        // decode next block into an accumulator.  Apply high bit if needed.
        a[0] = add!(
            a[0],
            and!(
                shift_right!(read32_little_endian!(&buf[0..]), 0),
                0x03FFFFFF
            )
        );
        a[1] = add!(
            a[1],
            and!(
                shift_right!(read32_little_endian!(&buf[3..]), 2),
                0x03FFFFFF
            )
        );
        a[2] = add!(
            a[2],
            and!(
                shift_right!(read32_little_endian!(&buf[6..]), 4),
                0x03FFFFFF
            )
        );
        a[3] = add!(
            a[3],
            and!(
                shift_right!(read32_little_endian!(&buf[9..]), 6),
                0x03FFFFFF
            )
        );
        a[4] = match buf_len < 16 && is_last {
            true => add!(
                a[4],
                or!(
                    shift_right!(read32_little_endian!(&buf[12..]), 8),
                    0x00000000
                )
            ),
            false => add!(
                a[4],
                or!(
                    shift_right!(read32_little_endian!(&buf[12..]), 8),
                    0x01000000
                )
            ),
        };

        // converts values into u64s to avoid overflow
        macro_rules! m {
            ($a:expr, $b:expr) => {{
                mult!($a as u64, $b as u64)
            }};
        }

        // multiply
        w[0] = add!(
            m!(a[0], r[0]),
            m!(a[1], mu[4]),
            m!(a[2], mu[3]),
            m!(a[3], mu[2]),
            m!(a[4], mu[1])
        );
        w[1] = add!(
            m!(a[0], r[1]),
            m!(a[1], r[0]),
            m!(a[2], mu[4]),
            m!(a[3], mu[3]),
            m!(a[4], mu[2])
        );
        w[2] = add!(
            m!(a[0], r[2]),
            m!(a[1], r[1]),
            m!(a[2], r[0]),
            m!(a[3], mu[4]),
            m!(a[4], mu[3])
        );
        w[3] = add!(
            m!(a[0], r[3]),
            m!(a[1], r[2]),
            m!(a[2], r[1]),
            m!(a[3], r[0]),
            m!(a[4], mu[4])
        );
        w[4] = add!(
            m!(a[0], r[4]),
            m!(a[1], r[3]),
            m!(a[2], r[2]),
            m!(a[3], r[1]),
            m!(a[4], r[0])
        );

        // modular reduction
        let mut c;
        c = shift_right!(w[0], 26);
        a[0] = and!(w[0] as u32, 0x3FFFFFF);
        w[1] = add!(w[1], c);
        c = shift_right!(w[1], 26);
        a[1] = and!(w[1] as u32, 0x3FFFFFF);
        w[2] = add!(w[2], c);
        c = shift_right!(w[2], 26);
        a[2] = and!(w[2] as u32, 0x3FFFFFF);
        w[3] = add!(w[3], c);
        c = shift_right!(w[3], 26);
        a[3] = and!(w[3] as u32, 0x3FFFFFF);
        w[4] = add!(w[4], c);
        c = shift_right!(w[4], 26);
        a[4] = and!(w[4] as u32, 0x3FFFFFF);

        a[0] = add!(a[0], mult!(c as u32, 5));
        a[1] = add!(a[1], shift_right!(a[0], 26));
        a[0] = and!(a[0], 0x3FFFFFF);

        // modify data.
        data = &data[buf_len..];
    }
}

// finishes authentication
pub fn poly1305_finish(tag: &mut [u8], a: &mut [u32], s: &[u32]) {
    // modular reduction
    let mut c;
    c = shift_right!(a[1], 26);
    a[1] = and!(a[1], 0x3ffffff);
    a[2] = add!(a[2], c);
    c = shift_right!(a[2], 26);
    a[2] = and!(a[2], 0x3ffffff);
    a[3] = add!(a[3], c);
    c = shift_right!(a[3], 26);
    a[3] = and!(a[3], 0x3ffffff);
    a[4] = add!(a[4], c);
    c = shift_right!(a[4], 26);
    a[4] = and!(a[4], 0x3ffffff);
    a[0] = add!(a[0], mult!(c, 5));
    c = shift_right!(a[0], 26);
    a[0] = and!(a[0], 0x3ffffff);
    a[1] = add!(a[1], c);

    // reduce if values is in the range (2^130-5, 2^130]
    let mut mux = greater_than!(a[0], 0x03FFFFFAu32);
    for i in 1..5 {
        mux = and!(mux, equal!(a[i], 0x03FFFFFF))
    }

    c = 5;
    for i in 0..5 {
        let mut t = add!(a[i], c);
        c = shift_right!(t, 26);
        t = and!(t, 0x03FFFFFF);
        a[i] = mux_bool!(mux, t, a[i]);
    }

    // convert back to 32bit words and add second half of key mod 2^128
    let mut word;
    word = add!(a[0] as u64, shift_left!(a[1] as u64, 26), s[0] as u64);
    write32_little_endian!(word as u32 => &mut tag[0..]);

    word = add!(
        shift_right!(word, 32),
        shift_left!(a[2] as u64, 20),
        s[1] as u64
    );
    write32_little_endian!(word as u32 => &mut tag[4..]);

    word = add!(
        shift_right!(word, 32),
        shift_left!(a[3] as u64, 14),
        s[2] as u64
    );
    write32_little_endian!(word as u32 => &mut tag[8..]);

    word = add!(shift_right!(word, 32) as u32, shift_left!(a[4], 8), s[3]) as u64;
    write32_little_endian!(word as u32 => &mut tag[12..]);
}
