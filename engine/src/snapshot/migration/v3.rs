// Copyright 2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::*;

/// Key size for the ephemeral key
const KEY_SIZE: usize = 32;
/// Key type alias.
pub type Key = [u8; KEY_SIZE];

const VERSION_V3: [u8; 2] = [0x3, 0x0];

#[allow(dead_code)]
pub(crate) fn read<I: Read>(input: &mut I, password: &Key) -> Result<Vec<u8>, Error> {
    let mut age = Vec::new();
    input.read_to_end(&mut age)?;
    age::decrypt_vec(password, age::RECOMMENDED_MAXIMUM_DECRYPT_WORK_FACTOR, &age[..]).map_err(From::from)
}

pub(crate) fn write<O: Write>(plain: &[u8], output: &mut O, password: &Key) -> Result<(), Error> {
    let work_factor = age::WorkFactor::new(age::RECOMMENDED_MINIMUM_ENCRYPT_WORK_FACTOR);
    let age = age::encrypt_vec(password, work_factor, plain).map_err(|_| Error::RngFailed)?;
    output.write_all(&age[..])?;
    Ok(())
}

/// Atomically encrypt, add magic and version bytes as file-header, and [`write`][self::write] the specified
/// plaintext to the specified path.
pub(crate) fn write_snapshot(plain: &[u8], path: &Path, password: &[u8]) -> Result<(), Error> {
    let compressed_plain = Zeroizing::new(compress(plain));

    // emulate constructor `KeyProvider::with_passphrase_hashed` with `D = blake2b`
    let mut password_hash = Zeroizing::new([0_u8; KEY_SIZE]);
    let mut h = crypto::hashes::blake2b::Blake2b256::default();
    h.update(password);
    h.finalize_into((password_hash.as_mut()).into());

    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    // write magic and version bytes
    f.write_all(&MAGIC)?;
    f.write_all(&VERSION_V3)?;
    // blake2b hash of password is used as encryption password in age
    write(&compressed_plain, &mut f, &password_hash)?;
    f.sync_all()?;

    Ok(())
}
