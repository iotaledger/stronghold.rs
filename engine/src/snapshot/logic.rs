// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    convert::TryInto,
    fs::{rename, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

use crypto::{keys::age, utils::rand};
use thiserror::Error as DeriveError;
use zeroize::Zeroizing;

use crate::snapshot::{compress, decompress};

/// Magic bytes (bytes 0-4 in a snapshot file) aka PARTI
pub const MAGIC: [u8; 5] = [0x50, 0x41, 0x52, 0x54, 0x49];

/// Current version bytes (bytes 5-6 in a snapshot file)
pub const VERSION: [u8; 2] = [0x3, 0x0];
// pub const OLD_VERSION: [u8; 2] = [0x2, 0x0];

/// Key size for the ephemeral key
pub const KEY_SIZE: usize = 32;
/// Key type alias.
pub type Key = [u8; KEY_SIZE];

#[derive(Debug, DeriveError)]
pub enum ReadError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("corrupted file: {0}")]
    CorruptedContent(String),

    #[error("invalid File: not a snapshot")]
    InvalidFile,

    #[error("unsupported version: expected `{expected:?}`, found `{found:?}`")]
    UnsupportedVersion { expected: [u8; 2], found: [u8; 2] },

    #[error("unsupported associated data")]
    UnsupportedAssociatedData,

    #[error("crypto error: {0:?}")]
    AgeFormatError(age::DecError),
}

impl From<age::DecError> for ReadError {
    fn from(e: age::DecError) -> Self {
        Self::AgeFormatError(e)
    }
}

impl From<ReadError> for crate::Error {
    fn from(e: ReadError) -> Self {
        Self::SnapshotError(format!("snapshot::ReadError: {e:?}").into())
    }
}

#[derive(Debug, DeriveError)]
pub enum WriteError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("generating random bytes failed: {0}")]
    GenerateRandom(String),

    #[error("corrupted data: {0}")]
    CorruptedData(String),

    #[error("unsupported associated data")]
    UnsupportedAssociatedData,

    #[error("incorrect work factor")]
    IncorrectWorkFactor,
}

impl From<WriteError> for crate::Error {
    fn from(e: WriteError) -> Self {
        Self::SnapshotError(format!("snapshot::WriteError: {e:?}").into())
    }
}

/// Encrypt snapshot content with key using work factor recommended for password-based (weak) keys.
///
/// # Security
///
/// Weak low-entropy (password-based) keys must be strengthened with key derivation.
/// Secure key derivation in this case is resource-consuming, ie. it can use a lot of RAM
/// and should take approx. 1 second. Strong keys generated with cryptographically secure RNG
/// don't need strengthening.
///
/// This function expects key to be password-based (blake2b hash of the user provided password).
/// It uses recommended work factor (approx. 20) to derive encryption key.
/// It is safe to use with strong keys, although computing resources may be wasted.
/// In this case it is recommended to use `encrypt_content_with_work_factor` with small/zero work factor.
pub fn encrypt_content<O: Write>(
    plain: &[u8],
    output: &mut O,
    key: &Key,
    associated_data: &[u8],
) -> Result<(), WriteError> {
    let work_factor = age::RECOMMENDED_MINIMUM_ENCRYPT_WORK_FACTOR;
    // TODO: work_factor is intentionally 0 just for development.
    // Use proper value in production.
    // let work_factor = 1;
    encrypt_content_with_work_factor(plain, output, key, work_factor, associated_data)
}

/// Encrypt snapshot content with key using custom work factor.
///
/// # Security warning
///
/// Work factor is used to strengthen weak low-entropy (password-based) keys.
/// Recommended value for such keys is approx. 20, ie. key derivation should take approx. 1 second.
/// Key derivation time grows exponentially with work factor.
///
/// Strong keys generated with cryptographically secure RNG do not need strengthening and
/// can use minimal (0) work factor.
///
/// Using low work factor with weak low-entropy keys can lead to full compromise of encrypted data!
pub fn encrypt_content_with_work_factor<O: Write>(
    plain: &[u8],
    output: &mut O,
    key: &Key,
    work_factor: u8,
    _associated_data: &[u8],
) -> Result<(), WriteError> {
    let work_factor = work_factor.try_into().map_err(|_| WriteError::IncorrectWorkFactor)?;
    let age = age::encrypt_vec(key, work_factor, plain)
        .map_err(|e| WriteError::GenerateRandom(format!("failed to generate age randomness: {e:?}")))?;
    output.write_all(&age[..])?;
    Ok(())
}

/// Decrypt snapshot content with key using maximum work factor recommended for password-based (weak) keys.
///
/// Decryption may fail if the required amount of computation (work factor) exceeds the recommended value.
/// In this case `decrypt_content_with_work_factor` with a larger work factor.
pub fn decrypt_content<I: Read>(
    input: &mut I,
    key: &Key,
    associated_data: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ReadError> {
    let max_work_factor = age::RECOMMENDED_MAXIMUM_DECRYPT_WORK_FACTOR;
    decrypt_content_with_work_factor(input, key, max_work_factor, associated_data)
}

/// Decrypt snapshot content with key using custom maximum work factor.
///
/// Decryption may fail if the required amount of computation (work factor) exceeds the provided value.
/// In this case a larger maximum work factor value can be used.
///
/// Strong keys are expected to use small/zero work factor.
/// Small/zero maximum work factor can be used in such case.
///
/// # Security
///
/// Key derivation time grows exponentially with work factor.
/// Maximum work factor should not be too large.
/// Large values of maximum work factor when exploited by an attacker can cause Denial-of-Service.
pub fn decrypt_content_with_work_factor<I: Read>(
    input: &mut I,
    key: &Key,
    max_work_factor: u8,
    _associated_data: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ReadError> {
    let mut age = Vec::new();
    input.read_to_end(&mut age)?;

    age::decrypt_vec(key, max_work_factor, &age[..])
        .map(Zeroizing::new)
        .map_err(From::from)
}

/// Put magic and version bytes as file-header, [`encrypt_content`][self::encrypt_content] the specified
/// plaintext to the specified path.
///
/// This is achieved by creating a temporary file in the same directory as the specified path (same
/// filename with a salted suffix). This is currently known to be problematic if the path is a
/// symlink and/or if the target path resides in a directory without user write permission.
pub fn encrypt_file(plain: &[u8], path: &Path, key: &Key, associated_data: &[u8]) -> Result<(), WriteError> {
    // TODO: if path exists and is a symlink, resolve it and then append the salt
    // TODO: if the sibling tempfile isn't writeable (e.g. directory permissions), write to
    if !associated_data.is_empty() {
        return Err(WriteError::UnsupportedAssociatedData);
    }

    let compressed_plain = Zeroizing::new(compress(plain));

    let mut salt = [0u8; 6];
    rand::fill(&mut salt).map_err(|e| WriteError::GenerateRandom(format!("{}", e)))?;

    let mut s = path.as_os_str().to_os_string();
    s.push(".");
    s.push(hex::encode(salt));
    let tmp = Path::new(&s);

    let mut f = OpenOptions::new().write(true).create_new(true).open(tmp)?;
    // write magic and version bytes
    f.write_all(&MAGIC)?;
    f.write_all(&VERSION)?;
    encrypt_content(&compressed_plain, &mut f, key, associated_data)?;
    f.sync_all()?;

    rename(tmp, path)?;

    Ok(())
}

/// Check the file header, [`decrypt_content`][self::decrypt_content], and decompress the ciphertext from the specified
/// path.
pub fn decrypt_file(path: &Path, key: &Key, associated_data: &[u8]) -> Result<Zeroizing<Vec<u8>>, ReadError> {
    let mut f: File = OpenOptions::new().read(true).open(path)?;
    check_min_file_len(&mut f)?;
    // check the header for structure.
    check_header(&mut f)?;
    if !associated_data.is_empty() {
        return Err(ReadError::UnsupportedAssociatedData);
    }
    let pt = Zeroizing::new(decrypt_content(&mut f, key, associated_data)?);

    decompress(&pt)
        .map(Zeroizing::new)
        .map_err(|e| ReadError::CorruptedContent(format!("Decompression failed: {}", e)))
}

fn check_min_file_len(input: &mut File) -> Result<(), ReadError> {
    const AGE_HEADER_LEN: usize = 150;
    const AGE_TAG_LEN: usize = 16;
    let min = MAGIC.len() + VERSION.len() + AGE_HEADER_LEN + AGE_TAG_LEN;
    if input.metadata()?.len() >= min as u64 {
        Ok(())
    } else {
        Err(ReadError::InvalidFile)
    }
}

/// Checks the header for a specific structure; explicitly the magic and version bytes.
fn check_header<I: Read>(input: &mut I) -> Result<(), ReadError> {
    // check the magic bytes
    let mut magic = [0u8; 5];
    input.read_exact(&mut magic)?;
    if magic != MAGIC {
        return Err(ReadError::InvalidFile);
    }

    // check the version
    let mut version = [0u8; 2];
    input.read_exact(&mut version)?;

    if version != VERSION {
        return Err(ReadError::UnsupportedVersion {
            expected: VERSION,
            found: version,
        });
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use stronghold_utils::test_utils::{corrupt, corrupt_file_at};

    fn variable_bytestring(max_len: usize) -> Vec<u8> {
        let mut len_bytes = [0_u8; (usize::BITS / 8) as usize];
        rand::fill(&mut len_bytes).unwrap();
        let len = usize::from_ne_bytes(len_bytes) % (max_len - 1) + 1;
        let mut bs = vec![0_u8; len];
        rand::fill(&mut bs).unwrap();
        bs
    }

    fn random_bytestring() -> Vec<u8> {
        variable_bytestring(4096)
    }

    fn random_key() -> Key {
        let mut key: Key = [0u8; KEY_SIZE];

        rand::fill(&mut key).expect("Unable to fill buffer");

        key
    }

    #[test]
    fn test_write_read() {
        let key: Key = random_key();
        let bs0 = random_bytestring();
        let ad = random_bytestring();

        let mut buf = Vec::new();
        encrypt_content(&bs0, &mut buf, &key, &ad).unwrap();
        let read = decrypt_content(&mut buf.as_slice(), &key, &ad).unwrap();
        assert_eq!(bs0, *read);
    }

    #[test]
    #[should_panic]
    fn test_corrupted_read_write() {
        let key: Key = random_key();
        let bs0 = random_bytestring();
        let ad = random_bytestring();

        let mut buf = Vec::new();
        encrypt_content(&bs0, &mut buf, &key, &ad).unwrap();
        corrupt(&mut buf);
        decrypt_content(&mut buf.as_slice(), &key, &ad).unwrap();
    }

    #[test]
    fn test_snapshot() {
        let f = tempfile::tempdir().unwrap();
        let mut pb = f.into_path();
        pb.push("snapshot");

        let key: Key = random_key();
        let bs0 = random_bytestring();

        encrypt_file(&bs0, &pb, &key, &[]).unwrap();
        let bs1 = decrypt_file(&pb, &key, &[]).unwrap();
        assert_eq!(bs0, *bs1);
    }

    #[test]
    #[should_panic]
    fn test_currupted_snapshot() {
        let f = tempfile::tempdir().unwrap();
        let mut pb = f.into_path();
        pb.push("snapshot");

        let key: Key = random_key();
        let bs0 = random_bytestring();

        encrypt_file(&bs0, &pb, &key, &[]).unwrap();
        corrupt_file_at(&pb);
        decrypt_file(&pb, &key, &[]).unwrap();
    }

    #[test]
    fn test_snapshot_overwrite() {
        let f = tempfile::tempdir().unwrap();
        let mut pb = f.into_path();
        pb.push("snapshot");

        encrypt_file(&random_bytestring(), &pb, &random_key(), &[]).unwrap();

        let key: Key = random_key();
        let bs0 = random_bytestring();
        encrypt_file(&bs0, &pb, &key, &[]).unwrap();
        let bs1 = decrypt_file(&pb, &key, &[]).unwrap();
        assert_eq!(bs0, *bs1);
    }

    struct TestVector {
        key: &'static str,
        ad: &'static str,
        data: &'static str,
        snapshot: &'static str,
    }

    #[test]
    fn test_vectors() {
        let tvs = [
            TestVector {
                key: "f6eafe6482445269d3228b3647001c283102116362e870644ba3bfc7f8f109e6",
                ad: "",
                data: "a0dcd6b9a95ca5321cefb443c3d19915eb269072929841d986306982a459229a1866479a64f5ed9ac31ea083ae73859b8e5a3ccd9e3045881602f2ed036d473ef09e88c488f4c0a95e823fd984a1ffd69a9a9d3f7ab63e9bd673020181363b9134f46aa6734a9a9600b01b35740f5161dfad303a8a85ad5edcef31bd76a8d47ae1a46e60824c1023401ddaa5d385f414cc2c1773aca240629e4a80149bdf992d97622c1775399a2c65d5f81f5cfcb79c894971b87a17f655c0c4b88b90ee2ad8bfdcd47d7566b33de7957a5c06d7d5b3cddcf55d45bb78c4d5099753edb51974ab01f9371140b89b56382c7bf28e62e246c2828e0ef45a991cd7b1e5a93ce5587b0e50792c2b44744121e84be0e3d6e01b2488d342622e1602d9a07eca27ffd83fb30e2c0b9700cf45080e415554b75ccfa08913acb9e8",
                snapshot: "504152544903006167652d656e6372797074696f6e2e6f72672f76310a2d3e20736372797074204d3970496c4d3164662b6353563366716831714465772031310a4e396f794d75686b396e2b75435663314355545555384b656c694f6c733239644d447433376d315a32546b0a2d2d2d204c4f34523579425864416f485865306369365358544d36487265487038527755656842544b444b2b75784d0a2d3ee7908d47abb031c93bcf816a92f09576f4a22301162f4f970c37b20cd242d416632dcdab4b98c50e7f8609945ba035cd2de4feb34bbb681c8541403a5e487602a281f357c8a6682206b277460ca0bf12a1143f5fd5dbbfba5045760bd2b0286a7cca3d5a980708e720424e6efe9b7c183eaadd26cc2f480cf5af1cf5e8175f0a41b8c12ebf7c7b23f6115d9d22ff9288f96099d62ffcd4c8483b30e805011ef172ac0b8aa53c65fa5cbd6ee675bd3c001d92039ab995efd52ad99fdb0156767771c20e73fd90990d6563d78ba923eed588cbd13bfa4288810cdca39541dbf48501b549c9d28cc387ac4c78ac78f753daf8d0418a70cf24d7de61cb9cc861b2be36102e3d3b6079e564b6aa895b1a5880c3d5bc86f10ec0463f076b1351bb5b280c578e5321666fcfe9c0e843a688f60d10b91c48995c4e003067ee8e07acdfa6f39242252d1c5c1442b57deec9c34ab56037d6021b",
            },
            TestVector {
                key: "683bd3d6957bf7276d0a616304f1610c57689a96d90118762f4caa9de9bc5bb6",
                ad: "",
                data: "",
                snapshot: "504152544903006167652d656e6372797074696f6e2e6f72672f76310a2d3e20736372797074202f754a34476a537776342b562f654546414e43586c512031310a705336736f573047302f63577a62434765534b6f35374b53614d52523842574c37435846664437383956340a2d2d2d206d73664263594c42686a526c785764727235624344367a5749774c586c6c4b5748706e4f65465732314c6b0a7903bc73e10ddb40152023255131650ec8c19d09c1c7c896db83ea0cc6a90d47",
            },
            TestVector {
                key: "cd250a0b070632dc521cfe35805b2846763a4c698d61d85d3b55f115b9a769da",
                ad: "",
                data: "",
                snapshot: "504152544903006167652d656e6372797074696f6e2e6f72672f76310a2d3e20736372797074204b5042447751786b4e346272584b41343844354a4f412031310a71637a6665775948683378747a5873626b5568662b556b6945796c646b74764b55464f6f525249516265510a2d2d2d20456a6e3850335447474b454a6150576c30432b78382f6a2b5037417755783261553675624a657a6e4767730a823a6568803ea775a18191ef7a9782569fe663f85caf15ecfb651ae485c65665",
            },
            TestVector {
                key: "9cf33b2539a3e9d89d2586ae6783d781de68df155eb2af22abaca3d6094d6db8",
                ad: "",
                data: "",
                snapshot: "504152544903006167652d656e6372797074696f6e2e6f72672f76310a2d3e20736372797074202b694b446c567a72434f764c77684e7a4535484345772031310a384768764d513331706c784270414b35364e3946646a593335374c71554730744b79516e6a45594d5951770a2d2d2d206d5a456b3139657456464d4e316c636a67765159746762515466752b3131337350684b4545767a457a396f0a081b254bda255364f9b91c8e89b921461db355a3d55a4222aefe66ced11ff6c5",
            },
        ];

        for tv in &tvs {
            let mut key = [0; KEY_SIZE];
            hex::decode_to_slice(tv.key, &mut key).unwrap();
            let ad = hex::decode(tv.ad).unwrap();
            let data = hex::decode(tv.data).unwrap();
            let snapshot = hex::decode(tv.snapshot).unwrap();

            let mut slice = snapshot.as_slice();

            // check the header for structure.
            check_header(&mut slice).unwrap();
            let pt = decrypt_content(&mut slice, &key, &ad).unwrap();

            assert_eq!(*pt, data);
        }
    }
}
