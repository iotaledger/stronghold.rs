// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub fn naive_kdf(password: &[u8], salt: &[u8; 32], key: &mut [u8; 32]) -> crate::Result<()> {
    crypto::macs::hmac::HMAC_SHA256(password, salt, key);
    Ok(())
}

/// derive a key from password and salt using the currently recommended key derivation function
/// and parameters
pub fn recommended_kdf(_password: &[u8], _salt: &[u8], _key: &mut [u8]) -> crate::Result<()> {
    todo!("argon2 with 'sensitive'/offline settings")
}
