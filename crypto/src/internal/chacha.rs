const BASIS: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

fn chacha20_rounds(state: &mut [u32]) {
    for _ in 0..10 {
        macro_rules! quarter_round {
            ($a:expr, $b:expr, $c:expr, $d:expr) => {{
                state[$a] = add!(state[$a], state[$b]);
                state[$d] = xor!(state[$d], state[$a]);
                state[$d] = or!(shift_left!(state[$d], 16), shift_right!(state[$d], 16));
                state[$c] = add!(state[$c], state[$d]);
                state[$b] = xor!(state[$b], state[$c]);
                state[$b] = or!(shift_left!(state[$b], 12), shift_right!(state[$b], 20));
                state[$a] = add!(state[$a], state[$b]);
                state[$d] = xor!(state[$d], state[$a]);
                state[$d] = or!(shift_left!(state[$d], 8), shift_right!(state[$d], 24));
                state[$c] = add!(state[$c], state[$d]);
                state[$b] = xor!(state[$b], state[$c]);
                state[$b] = or!(shift_left!(state[$b], 7), shift_right!(state[$b], 25));
            }};
        }

        quarter_round!(0, 4, 8, 12);
        quarter_round!(1, 5, 9, 13);
        quarter_round!(2, 6, 10, 14);
        quarter_round!(3, 7, 11, 15);
        quarter_round!(0, 5, 10, 15);
        quarter_round!(1, 6, 11, 12);
        quarter_round!(2, 7, 8, 13);
        quarter_round!(3, 4, 9, 14);
    }
}

pub fn h_chacha20_hash(key: &[u8], nonce: &[u8], buf: &mut [u8]) {
    let mut state = vec![0u32; 16];
    (0..4).for_each(|i| state[i] = BASIS[i]);
    (4..12).for_each(|i| state[i] = read32_little_endian!(&key[(i - 4) * 4..]));
    (12..16).for_each(|i| state[i] = read32_little_endian!(&nonce[(i - 12) * 4..]));

    chacha20_rounds(&mut state);

    let (buf_a, buf_b) = buf.split_at_mut(16);
    (0..4).for_each(|i| write32_little_endian!(state[i] => &mut buf_a[i* 4..]));
    (12..16).for_each(|i| write32_little_endian!(state[i] => &mut buf_b[(i - 12) * 4..]));
}

pub fn chacha20_ietf_block(key: &[u8], nonce: &[u8], n: u32, buf: &mut [u8]) {
    let mut state = vec![0u32; 32];
    let (init, mixed) = state.split_at_mut(16);

    (0..4).for_each(|i| init[i] = BASIS[i]);
    (4..12).for_each(|i| init[i] = read32_little_endian!(&key[(i - 4) * 4..]));
    init[12] = n;
    (13..16).for_each(|i| init[i] = read32_little_endian!(&nonce[(i - 13) * 4..]));

    mixed.copy_from_slice(init);
    chacha20_rounds(mixed);
    (0..16).for_each(|i| mixed[i] = add!(mixed[i], init[i]));
    (0..16).for_each(|i| write32_little_endian!(mixed[i] => &mut buf[i * 4..]));
}

pub fn chacha20_block(key: &[u8], nonce: &[u8], n: u64, buf: &mut [u8]) {
    let mut state = vec![0u32; 32];
    let (init, mixed) = state.split_at_mut(16);

    (0..4).for_each(|i| init[i] = BASIS[i]);
    (4..12).for_each(|i| init[i] = read32_little_endian!(&key[(i - 4) * 4..]));
    split64_little_endian!(n => &mut init[12..]);
    (14..16).for_each(|i| init[i] = read32_little_endian!(&nonce[(i - 14) * 4..]));

    mixed.copy_from_slice(init);
    chacha20_rounds(mixed);

    (0..16).for_each(|i| mixed[i] = add!(mixed[i], init[i]));
    (0..16).for_each(|i| write32_little_endian!(mixed[i] => &mut buf[i * 4..]));
}
