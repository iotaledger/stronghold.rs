// Copyright 2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use engine::snapshot::migration::{migrate, Version};
use std::path::Path;

fn main() {
    let mut key = [0_u8; 32];
    let password = b"migration-test";
    let salt = b"wallet.rs";
    let iter = core::num::NonZeroU32::new(100).unwrap();
    crypto::keys::pbkdf::PBKDF2_HMAC_SHA512(password, salt, iter, &mut key);

    let v2 = Version::v2(Path::new("../stardust-cli-wallet.stronghold"), &key, &[]);
    let v3 = Version::v3(Path::new("../stardust-cli-wallet-v3.stronghold"), b"migration-test");
    println!("migrating: {:?}", migrate(v2, v3));
}
