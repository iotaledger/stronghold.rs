// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crypto::hashes::{blake2b::Blake2b256, Digest};
use zeroize::Zeroizing;

pub fn hash_blake2b(input: String) -> Zeroizing<Vec<u8>> {
    let mut hasher = Blake2b256::new();
    hasher.update(input.as_bytes());
    let mut hash = Zeroizing::new(vec![0_u8; Blake2b256::output_size()]);
    hasher.finalize_into((&mut hash[..]).into());
    hash
}
