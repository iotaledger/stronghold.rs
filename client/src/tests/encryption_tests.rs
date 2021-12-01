// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crypto::{
    ciphers::{chacha::XChaCha20Poly1305, traits::Aead},
    hashes::blake2b::Blake2b256,
    keys::x25519,
};
use digest::Digest;
use generic_array as A;

#[test]
fn test_asymmetric_symmetric_encryption() {
    // initialize default hasher
    let mut blake2b = Blake2b256::default();

    let plaintext = "this is some plaintext.";
    let plaintext_bytes_len = plaintext.as_bytes().len();

    // create random secret keys
    let secret_a = x25519::SecretKey::generate().unwrap();
    let secret_b = x25519::SecretKey::generate().unwrap();

    // derive public keys
    let public_a = secret_a.public_key();
    let public_b = secret_b.public_key();

    // create shared secrets
    let shared_b = secret_b.diffie_hellman(&public_a).to_bytes();
    let shared_a = secret_a.diffie_hellman(&public_b).to_bytes();

    // allocate tags
    let mut tag_a = [0u8; XChaCha20Poly1305::TAG_LENGTH];
    let mut tag_b = [0u8; XChaCha20Poly1305::TAG_LENGTH];

    // pre-allocate cipher texts
    let mut cipher_a = vec![0u8; plaintext_bytes_len];
    let mut cipher_b = vec![0u8; plaintext_bytes_len];

    let mut plain_a = vec![0u8; plaintext_bytes_len];
    let mut plain_b = vec![0u8; plaintext_bytes_len];

    // encryption pass
    {
        // encryption from a
        if let Err(error) = encrypt(&shared_a, plaintext.as_bytes(), &mut cipher_a, &mut blake2b, &mut tag_a) {
            panic!("Error {}", error)
        }

        // encryption from b
        if let Err(error) = encrypt(&shared_b, plaintext.as_bytes(), &mut cipher_b, &mut blake2b, &mut tag_b) {
            panic!("Error {}", error)
        }

        // check result
        assert_eq!(cipher_a, cipher_b);
    }

    // decryption pass
    {
        if let Err(error) = decrypt(&shared_a, &mut plain_a, &cipher_a, &mut blake2b, &tag_a) {
            panic!("Error {}", error)
        }

        if let Err(error) = decrypt(&shared_b, &mut plain_b, &cipher_b, &mut blake2b, &tag_b) {
            panic!("Error {}", error)
        }

        assert_eq!(plain_a, plain_b);
    }
}
/// Encrypts `plaintext` with `key` hashed with `digest` and store ciphertext in `cipher`
fn encrypt<D>(shared: &[u8], plaintext: &[u8], cipher: &mut [u8], digest: &mut D, tag: &mut [u8]) -> crypto::Result<()>
where
    D: Digest,
{
    // create hashed key
    let mut key = [0u8; XChaCha20Poly1305::KEY_LENGTH];
    digest.update(&shared);
    key.clone_from_slice(digest.finalize_reset().as_slice());

    // create pseudo nonce
    let nonce = A::GenericArray::from([0u8; XChaCha20Poly1305::NONCE_LENGTH]);

    // create key
    let key = A::GenericArray::from(key);

    // symmetrically encrypt with shared_a
    XChaCha20Poly1305::encrypt(&key, &nonce, b"", plaintext, cipher, tag.into())
}

/// Decrypts `cipher` with `key` hashed with `digest` and store plaintext in `plaintext`
fn decrypt<D>(shared: &[u8], plaintext: &mut [u8], cipher: &[u8], digest: &mut D, tag: &[u8]) -> crypto::Result<usize>
where
    D: Digest,
{
    // create hashed key
    let mut key = [0u8; XChaCha20Poly1305::KEY_LENGTH];
    digest.update(&shared);
    key.clone_from_slice(digest.finalize_reset().as_slice());

    // create pseudo nonce
    let nonce = A::GenericArray::from([0u8; XChaCha20Poly1305::NONCE_LENGTH]);

    // create key
    let key = A::GenericArray::from(key);

    XChaCha20Poly1305::decrypt(&key, &nonce, b"", plaintext, cipher, tag.into())
}
