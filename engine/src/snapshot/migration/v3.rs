use super::*;

/// Key size for the ephemeral key
const KEY_SIZE: usize = 32;
/// Key type alias.
pub type Key = [u8; KEY_SIZE];

const VERSION_V3: [u8; 2] = [0x3, 0x0];

#[allow(dead_code)]
pub(crate) fn read<I: Read>(input: &mut I, password: &Key, _associated_data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut age = Vec::new();
    input.read_to_end(&mut age)?;
    age::decrypt_vec(password, age::RECOMMENDED_MAXIMUM_DECRYPT_WORK_FACTOR, &age[..]).map_err(|e| Error::AgeError(e))
}

pub(crate) fn write<O: Write>(
    plain: &[u8],
    output: &mut O,
    password: &Key,
    _associated_data: &[u8],
) -> Result<(), Error> {
    let work_factor = age::WorkFactor::new(age::RECOMMENDED_MINIMUM_ENCRYPT_WORK_FACTOR);
    let age = age::encrypt_vec(password, work_factor, plain)
        .map_err(|_| Error::EncryptFailed)?;
    output.write_all(&age[..])?;
    Ok(())
}

/// Atomically encrypt, add magic and version bytes as file-header, and [`write`][self::write] the specified
/// plaintext to the specified path.
///
/// This is achieved by creating a temporary file in the same directory as the specified path (same
/// filename with a salted suffix). This is currently known to be problematic if the path is a
/// symlink and/or if the target path resides in a directory without user write permission.
pub(crate) fn write_snapshot(plain: &[u8], path: &Path, password: &[u8], aad: &[u8]) -> Result<(), Error> {
    guard(aad.is_empty(), Error::AadNotSupported)?;
    let compressed_plain = compress(plain);

    // emulate constructor `KeyProvider::with_passphrase_hashed` with `D = blake2b`
    let mut password_hash = [0_u8; KEY_SIZE];
    let mut h = crypto::hashes::blake2b::Blake2b256::default();
    h.update(password);
    h.finalize_into((&mut password_hash).into());

    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    // write magic and version bytes
    f.write_all(&MAGIC)?;
    f.write_all(&VERSION_V3)?;
    // blake2b hash of password is used as encryption password in age
    write(&compressed_plain, &mut f, &password_hash, aad)?;
    f.sync_all()?;

    Ok(())
}
