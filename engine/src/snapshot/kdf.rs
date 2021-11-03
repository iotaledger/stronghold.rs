// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/// a wrapper around the [`HMAC_SHA256`] function used to derive a hash from a given password.
pub fn naive_kdf(password: &[u8], salt: &[u8; 32], key: &mut [u8; 32]) {
    crypto::macs::hmac::HMAC_SHA256(password, salt, key);
}
