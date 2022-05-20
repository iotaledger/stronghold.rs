// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
use crypto::hashes::{blake2b::Blake2b256, Digest};

pub fn hash_blake2b(input: String) -> Vec<u8> {
    let mut hasher = Blake2b256::new();
    hasher.update(input.as_bytes());
    hasher.finalize().to_vec()
}
