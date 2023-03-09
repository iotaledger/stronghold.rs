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
pub(crate) fn read<I: Read>(input: &mut I, key: &Key, associated_data: &[u8]) -> Result<Vec<u8>, Error> {
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
#[allow(dead_code)]
pub(crate) fn write<O: Write>(plain: &[u8], output: &mut O, key: &Key, associated_data: &[u8]) -> Result<(), Error> {
    // create ephemeral key pair.
    let ephemeral_key = x25519::SecretKey::generate()?;

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
/// Dependencies (should not change):
///
/// - `crypto.rs`
/// - `crate::snapshot::decompress`
pub(crate) fn read_snapshot(path: &Path, key: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>, Error> {
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

    let pt = read(&mut f, key, aad)?;

    decompress(&pt).map_err(|_| Error::DecompressFailed)
}
