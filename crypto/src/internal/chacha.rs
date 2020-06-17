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
