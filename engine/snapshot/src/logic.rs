// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    fs::File,
    io::{Read, Write},
    fs::OpenOptions,
    path::Path,
};

use crypto::{
    ciphers::chacha::xchacha20poly1305,
};

/// PARTI in binary
const MAGIC: [u8; 5] = [0x50, 0x41, 0x52, 0x54, 0x49];

/// version 1.0 in binary
const VERSION: [u8; 2] = [0x1, 0x0];

const KEY_SIZE: usize = 32;
pub type Key = [u8; KEY_SIZE];

/// encrypt and write a serialized snapshot
pub fn write<O: Write>(input: &[u8], out: &mut O, key: &Key, associated_data: &[u8]) -> crate::Result<()> {
    out.write_all(&MAGIC)?;
    out.write_all(&VERSION)?;

    let mut nonce = [0; xchacha20poly1305::XCHACHA20POLY1305_NONCE_SIZE];
    crypto::rand::fill(&mut nonce)?;
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

/// decrypt a snapshot and return its serialized bytes
pub fn read<I: Read>(input: &mut I, key: &Key, associated_data: &[u8]) -> crate::Result<Vec<u8>> {
    // check the header
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

pub fn write_to(input: &[u8], path: &Path, key: &Key, associated_data: &[u8]) -> crate::Result<()> {
    let mut f = OpenOptions::new().write(true).create(true).open(path)?;
    write(input, &mut f, key, associated_data)?;
    f.sync_all()?;
    Ok(())
}

pub fn read_from(path: &Path, key: &Key, associated_data: &[u8]) -> crate::Result<Vec<u8>> {
    let mut f: File = OpenOptions::new().read(true).open(path)?;
    check_min_file_len(&mut f)?;
    read(&mut f, key, associated_data)
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

fn check_header<I: Read>(input: &mut I) -> crate::Result<()> {
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
    use crate::test_utils::{fresh, seek_to_beginning, corrupt_file, corrupt_file_at};

    #[test]
    fn test_write_read() -> crate::Result<()> {
        let mut f = tempfile::tempfile().unwrap();
        let key: Key = rand::random();
        let bs0 = fresh::bytestring();
        let ad = fresh::bytestring();

        write(&bs0, &mut f, &key, &ad)?;
        seek_to_beginning(&mut f);
        let bs1 = read(&mut f, &key, &ad)?;

        assert_eq!(bs0, bs1);

        Ok(())
    }

    #[test]
    #[should_panic]
    fn test_corrupted_read_write() -> () {
        let mut f = tempfile::tempfile().unwrap();
        let key: Key = rand::random();
        let bs0 = fresh::bytestring();
        let ad = fresh::bytestring();

        write(&bs0, &mut f, &key, &ad).unwrap();
        corrupt_file(&mut f);
        read(&mut f, &key, &ad).unwrap();
    }

    #[test]
    fn test_snapshot() -> crate::Result<()> {
        let f = tempfile::tempdir().unwrap();
        let mut pb = f.into_path();
        pb.push("snapshot");

        let key: Key = rand::random();
        let bs0 = fresh::bytestring();
        let ad = fresh::bytestring();

        write_to(&bs0, &pb, &key, &ad)?;
        let bs1 = read_from(&pb, &key, &ad)?;

        assert_eq!(bs0, bs1);

        Ok(())
    }

    #[test]
    #[should_panic]
    fn test_currupted_snapshot() {
        let f = tempfile::tempdir().unwrap();
        let mut pb = f.into_path();
        pb.push("snapshot");

        let key: Key = rand::random();
        let bs0 = fresh::bytestring();
        let ad = fresh::bytestring();

        write_to(&bs0, &pb, &key, &ad).unwrap();
        corrupt_file_at(&pb);
        read_from(&pb, &key, &ad).unwrap();
    }
}
