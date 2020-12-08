// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    fs::File,
    io::{Read, Write},
};

use crypto::{
    ciphers::chacha::xchacha20poly1305,
    rand,
};

/// PARTI in binary
const MAGIC: [u8; 5] = [0x50, 0x41, 0x52, 0x54, 0x49];

/// version 1.0 in binary
const VERSION: [u8; 2] = [0x1, 0x0];

type Key = [u8; 32];

/// encrypt and write a serialized snapshot to a file
pub fn encrypt_snapshot(input: &[u8], out: &mut File, key: &Key, associated_data: &[u8]) -> crate::Result<()> {
    out.write_all(&MAGIC)?;
    out.write_all(&VERSION)?;

    let mut nonce = [0; xchacha20poly1305::XCHACHA20POLY1305_NONCE_SIZE];
    rand::fill(&mut nonce)?;
    out.write_all(&nonce)?;

    let mut tag = [0; xchacha20poly1305::XCHACHA20POLY1305_TAG_SIZE];
    let mut ct = vec![0; input.len()];
    xchacha20poly1305::encrypt(
        &mut ct,
        &mut tag,
        input,
        key,
        &nonce,
        associated_data)?;

    out.write_all(&tag)?;
    out.write_all(&ct)?;

    Ok(())
}

/// decrypt a snapshot file and return its serialized bytes
pub fn decrypt_snapshot(input: &mut File, key: &Key, associated_data: &[u8]) -> crate::Result<Vec<u8>> {
    // check the file len and header
    check_min_file_len(input)?;
    check_header(input)?;

    let mut nonce = [0; xchacha20poly1305::XCHACHA20POLY1305_NONCE_SIZE];
    input.read_exact(&mut nonce)?;

    let mut tag = [0; xchacha20poly1305::XCHACHA20POLY1305_TAG_SIZE];
    input.read_exact(&mut tag)?;

    let mut ct = Vec::new();
    input.read_to_end(&mut ct)?;

    let mut pt = vec![0; ct.len()];
    xchacha20poly1305::decrypt(
        &mut pt,
        &ct,
        key,
        &tag,
        &nonce,
        associated_data)?;

    Ok(pt)
}

/// check to see if the file is long enough.
fn check_min_file_len(input: &mut File) -> crate::Result<()> {
    let min = MAGIC.len() + VERSION.len()
        + xchacha20poly1305::XCHACHA20POLY1305_NONCE_SIZE
        + xchacha20poly1305::XCHACHA20POLY1305_TAG_SIZE;
    if input.metadata()?.len() >= min as u64 {
        Ok(())
    } else {
        Err(crate::Error::SnapshotError("Snapshot is too short to be valid".into()))
    }
}

fn check_header(input: &mut File) -> crate::Result<()> {
    // check the magic bytes
    let mut magic = [0u8; 5];
    input.read_exact(&mut magic)?;
    if magic != MAGIC {
        return Err(crate::Error::SnapshotError("magic bytes mismatch, is this really a snapshot file?".into()));
    }

    // check the version
    let mut version = [0u8; 2];
    input.read_exact(&mut version)?;
    if version != VERSION {
        return Err(crate::Error::SnapshotError("snapshot version is incorrect".into()));
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_snapshot() -> crate::Result<()> {
        Ok(())
    }
}
