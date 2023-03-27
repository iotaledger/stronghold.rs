// Copyright 2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod error;
mod v2;
mod v3;

use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

use crypto::{
    ciphers::{chacha::XChaCha20Poly1305, traits::Aead},
    hashes::{blake2b, Digest},
    keys::{age, x25519},
};

// These dependencies must not change between versions,
// otherwise migration will work differently.
pub use self::error::Error;
use crate::snapshot::{compress, decompress};
use zeroize::Zeroizing;

pub enum Version<'a> {
    V2 {
        path: &'a Path,
        key: &'a [u8; 32],
        aad: &'a [u8],
    },
    V3 {
        path: &'a Path,
        password: &'a [u8],
    },
}

impl<'a> Version<'a> {
    pub fn v2(path: &'a Path, key: &'a [u8; 32], aad: &'a [u8]) -> Self {
        Self::V2 { path, key, aad }
    }

    pub fn v3(path: &'a Path, password: &'a [u8]) -> Self {
        Self::V3 { path, password }
    }
}

/// Magic bytes (bytes 0-4 in a snapshot file) aka PARTI
const MAGIC: [u8; 5] = [0x50, 0x41, 0x52, 0x54, 0x49];

#[inline]
fn guard<E>(cond: bool, err: E) -> Result<(), E> {
    if cond {
        Ok(())
    } else {
        Err(err)
    }
}

fn migrate_from_v2_to_v3(
    v2_path: &Path,
    v2_key: &[u8; 32],
    v2_aad: &[u8],
    v3_path: &Path,
    v3_pwd: &[u8],
) -> Result<(), Error> {
    let v = v2::read_snapshot(v2_path, v2_key, v2_aad)?;
    v3::write_snapshot(&v[..], v3_path, v3_pwd, &[])
}

pub fn migrate(prev: Version, next: Version) -> Result<(), Error> {
    match (prev, next) {
        (
            Version::V2 {
                path: v2_path,
                key: v2_key,
                aad: v2_aad,
            },
            Version::V3 {
                path: v3_path,
                password: v3_pwd,
            },
        ) => migrate_from_v2_to_v3(v2_path, v2_key, v2_aad, v3_path, v3_pwd),
        _ => Err(Error::BadMigrationVersion),
    }
}
