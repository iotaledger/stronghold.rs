// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/// derive key from password and salt
pub fn derive_key_from_password(_password: &[u8], _salt: &[u8], _key: &mut [u8]) -> crate::Result<()> {
    todo!("argon2 with 'sensitive'/offline settings");
}
