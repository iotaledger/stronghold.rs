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

use thiserror::Error as DeriveError;
use zeroize::Zeroize;

// These dependencies must not change between versions,
// otherwise migration will work differently.
use crate::snapshot::{compress, decompress};

#[derive(Debug, DeriveError)]
pub enum Error {
    /// Can't migrate between selected versions.
    #[error("Can't migrate between selected versions")]
    BadMigrationVersion,
    /// Input snapshot has incorrect/unexpected version.
    #[error("Input snapshot has incorrect/unexpected version")]
    BadSnapshotVersion,
    /// Input file has incorrect format.
    #[error("Input file has incorrect format")]
    BadSnapshotFormat,
    /// Failed to decrypt snapshot: incorrect password or corrupt data.
    #[error("Failed to decrypt snapshot: incorrect password or corrupt data")]
    DecryptFailed,
    /// Failed to decompress snapshot.
    #[error("Failed to decompress snapshot")]
    DecompressFailed,
    /// Authenticated associated data is not supported by snapshot format.
    #[error("Authenticated associated data is not supported by snapshot format")]
    AadNotSupported,
    /// Failed to encrypt.
    #[error("Failed to encrypt")]
    EncryptFailed,
    /// Age format error.
    #[error("Age format error")]
    AgeError(age::Error),
    /// I/O error.
    #[error("I/O error")]
    IoError(std::io::Error),
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

pub enum Version<'a> {
    V2wallet {
        path: &'a Path,
        password: &'a [u8],
        aad: &'a [u8],
    },
    V3 {
        path: &'a Path,
        password: &'a [u8],
        aad: &'a [u8],
    },
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

mod v2 {
    use super::*;

    /// Key size for the ephemeral key
    const KEY_SIZE: usize = 32;
    /// Key type alias.
    pub type Key = [u8; KEY_SIZE];

    /// Nonce size for XChaCha20Poly1305
    const NONCE_SIZE: usize = XChaCha20Poly1305::NONCE_LENGTH;
    /// Nonce type alias
    pub type Nonce = [u8; NONCE_SIZE];

    const VERSION_V2: [u8; 2] = [0x2, 0x0];

    /// Read ciphertext from the input, decrypts it using the specified key and the associated data
    /// specified during encryption and returns the plaintext
    pub fn read<I: Read>(input: &mut I, key: &Key, associated_data: &[u8]) -> Result<Vec<u8>, Error> {
        // create ephemeral private key.
        let mut ephemeral_pk = [0; x25519::PUBLIC_KEY_LENGTH];
        // get ephemeral private key from input.
        input.read_exact(&mut ephemeral_pk)?;

        // creating the secret key now expects an array
        let mut key_bytes = [0u8; x25519::SECRET_KEY_LENGTH];
        key_bytes.clone_from_slice(key);

        // derive public key from ephemeral private key
        let ephemeral_pk = x25519::PublicKey::from_bytes(ephemeral_pk);

        // get x25519 key pair from ephemeral private key.
        let sk = x25519::SecretKey::from_bytes(key_bytes);
        let pk = sk.public_key();

        // diffie hellman to create the shared secret.
        let shared = sk.diffie_hellman(&ephemeral_pk);

        // compute the nonce using the ephemeral keys.
        let nonce = {
            let mut i = ephemeral_pk.to_bytes().to_vec();
            i.extend_from_slice(&pk.to_bytes());
            let res = blake2b::Blake2b256::digest(&i).to_vec();
            let v: Nonce = res[0..NONCE_SIZE].try_into().expect("slice with incorrect length");
            v
        };

        // create and read tag from input.
        let mut tag = [0; XChaCha20Poly1305::TAG_LENGTH];
        input.read_exact(&mut tag)?;

        // create and read ciphertext from input.
        let mut ct = Vec::new();
        input.read_to_end(&mut ct)?;

        // create plain text buffer.
        let mut pt = vec![0; ct.len()];

        // decrypt the ciphertext into the plain text buffer.
        XChaCha20Poly1305::try_decrypt(&shared.to_bytes(), &nonce, associated_data, &mut pt, &ct, &tag)
            .map_err(|_| Error::DecryptFailed)?;

        Ok(pt)
    }

    /// Encrypt the opaque plaintext bytestring using the specified [`Key`] and optional associated data
    /// and writes the ciphertext to the specifed output
    #[deprecated]
    pub fn write<O: Write>(plain: &[u8], output: &mut O, key: &Key, associated_data: &[u8]) -> Result<(), Error> {
        // create ephemeral key pair.
        let ephemeral_key = x25519::SecretKey::generate().unwrap();

        // get public key.
        let ephemeral_pk = ephemeral_key.public_key();

        let ephemeral_pk_bytes = ephemeral_pk.to_bytes();

        // write public key into output.
        output.write_all(&ephemeral_pk_bytes)?;

        // secret key now expects an array
        let mut key_bytes = [0u8; x25519::SECRET_KEY_LENGTH];
        key_bytes.clone_from_slice(key);

        // get `x25519` secret key from public key.
        let pk = x25519::SecretKey::from_bytes(key_bytes).public_key();

        let pk_bytes = pk.to_bytes();

        // do a diffie_hellman exchange to make a shared secret key.
        let shared = ephemeral_key.diffie_hellman(&pk);

        // compute the nonce using the ephemeral keys.
        let nonce = {
            let mut i = ephemeral_pk.to_bytes().to_vec();
            i.extend_from_slice(&pk_bytes);
            let res = blake2b::Blake2b256::digest(&i).to_vec();
            let v: Nonce = res[0..NONCE_SIZE].try_into().expect("slice with incorrect length");
            v
        };

        // create the XChaCha20Poly1305 tag.
        let mut tag = [0; XChaCha20Poly1305::TAG_LENGTH];

        // creates the ciphertext.
        let mut ct = vec![0; plain.len()];

        // decrypt the plain text into the ciphertext buffer.
        XChaCha20Poly1305::try_encrypt(&shared.to_bytes(), &nonce, associated_data, plain, &mut ct, &mut tag)
            .map_err(|_| Error::EncryptFailed)?;

        // write tag and ciphertext into the output.
        output.write_all(&tag)?;
        output.write_all(&ct)?;

        Ok(())
    }

    /// Read & decrypt V2wallet snapshot file.
    ///
    /// Relevant references:
    ///
    /// - [PBKDF2 in crypto.rs](https://github.com/iotaledger/crypto.rs/blob/3c5c415ff44a6106e4b133dd157d846363e07ebe/src/keys/pbkdf.rs#L32)
    /// - [wallet.rs style to create KeyProvider in iota.rs](https://github.com/iotaledger/iota.rs/blob/03c72133279b98f12c91b1e1bdc14965d9f48cf9/client/src/stronghold/common.rs#L33)
    /// - [KeyProvider constructor in stronghold.rs](https://github.com/iotaledger/stronghold.rs/blob/c2dfa5f9f1f32220d377ed64d934947b22943a5f/client/src/security/keyprovider.rs#L80)
    ///
    /// Dependencies:
    ///
    /// - `crypto.rs`
    /// - `crate::snapshot::decompress`
    ///
    pub fn read_wallet_snapshot(path: &Path, password: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
        const PBKDF_SALT: &[u8] = b"wallet.rs";
        const PBKDF_ITER: usize = 100;
        const KEY_SIZE_HASHED: usize = 32;

        // "wallet.rs"-style of deriving KeyProvider from password

        // Hash a password, deriving a key, for accessing Stronghold.
        let mut buffer = [0u8; 64];

        // Safe to unwrap because rounds > 0.
        crypto::keys::pbkdf::PBKDF2_HMAC_SHA512(password, PBKDF_SALT, PBKDF_ITER, buffer.as_mut()).unwrap();

        // key internally stored in KeyProvider
        let mut key = [0_u8; KEY_SIZE_HASHED];
        key.copy_from_slice(&buffer[..KEY_SIZE_HASHED]);
        buffer.zeroize();

        let mut f: File = OpenOptions::new().read(true).open(path)?;

        // check min file length
        const MIN_LEN: u64 =
            (MAGIC.len() + VERSION_V2.len() + x25519::PUBLIC_KEY_LENGTH + XChaCha20Poly1305::TAG_LENGTH) as u64;
        guard(f.metadata()?.len() >= MIN_LEN, Error::BadSnapshotFormat)?;

        // check the magic bytes
        let mut magic = [0u8; 5];
        f.read_exact(&mut magic)?;
        guard(magic == MAGIC, Error::BadSnapshotFormat)?;

        // check the version
        let mut version = [0u8; 2];
        f.read_exact(&mut version)?;
        guard(version == VERSION_V2, Error::BadSnapshotVersion)?;

        let pt = read(&mut f, &key, aad)?;
        key.zeroize();

        decompress(&pt).map_err(|_| Error::DecompressFailed)
    }
}

mod v3 {
    use super::*;

    /// Key size for the ephemeral key
    const KEY_SIZE: usize = 32;
    /// Key type alias.
    pub type Key = [u8; KEY_SIZE];

    const VERSION_V3: [u8; 2] = [0x3, 0x0];

    pub fn read<I: Read>(input: &mut I, key: &Key, _associated_data: &[u8]) -> Result<Vec<u8>, Error> {
        let mut age = Vec::new();
        input.read_to_end(&mut age)?;
        age::decrypt_vec(key, &age[..]).map_err(|e| Error::AgeError(e))
    }

    pub fn write<O: Write>(plain: &[u8], output: &mut O, key: &Key, _associated_data: &[u8]) -> Result<(), Error> {
        let age = age::encrypt_vec(key, plain);
        output.write_all(&age[..])?;
        Ok(())
    }

    /// Atomically encrypt, add magic and version bytes as file-header, and [`write`][self::write] the specified
    /// plaintext to the specified path.
    ///
    /// This is achieved by creating a temporary file in the same directory as the specified path (same
    /// filename with a salted suffix). This is currently known to be problematic if the path is a
    /// symlink and/or if the target path resides in a directory without user write permission.
    pub fn write_snapshot(plain: &[u8], path: &Path, password: &[u8], aad: &[u8]) -> Result<(), Error> {
        guard(aad.is_empty(), Error::AadNotSupported)?;
        let compressed_plain = compress(plain);

        // emulate constructor `KeyProvider::with_passphrase_hashed` with `D = blake2b`
        let mut key = [0_u8; KEY_SIZE];
        let mut h = crypto::hashes::blake2b::Blake2b256::default();
        h.update(password);
        h.finalize_into((&mut key).into());

        let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
        // write magic and version bytes
        f.write_all(&MAGIC)?;
        f.write_all(&VERSION_V3)?;
        write(&compressed_plain, &mut f, &key, aad)?;
        f.sync_all()?;

        Ok(())
    }
}

fn migrate_from_v2wallet_to_v3(
    prev_path: &Path,
    prev_pwd: &[u8],
    prev_aad: &[u8],
    next_path: &Path,
    next_pwd: &[u8],
    next_aad: &[u8],
) -> Result<(), Error> {
    let v = v2::read_wallet_snapshot(prev_path, prev_pwd, prev_aad)?;
    v3::write_snapshot(&v[..], next_path, next_pwd, next_aad)
}

pub fn migrate(prev: Version, next: Version) -> Result<(), Error> {
    match (prev, next) {
        (
            Version::V2wallet {
                path: prev_path,
                password: prev_pwd,
                aad: prev_aad,
            },
            Version::V3 {
                path: next_path,
                password: next_pwd,
                aad: next_aad,
            },
        ) => migrate_from_v2wallet_to_v3(prev_path, prev_pwd, prev_aad, next_path, next_pwd, next_aad),
        _ => Err(Error::BadMigrationVersion),
    }
}
