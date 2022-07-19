// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crypto::hashes::Digest;
use engine::{
    runtime::{
        locked_memory::LockedMemory,
        memories::buffer::{Buffer, Ref},
        Bytes, MemoryError,
    },
    vault::NCKey,
};
use std::ops::Deref;
use stronghold_utils::GuardDebug;
use zeroize::Zeroize;

use crate::{internal::Provider, ClientError};

/// This constant will be used to truncate a supplied passphrase
const KEY_SIZE_HASHED: usize = 32;

/// The [`KeyProvider`] keeps secrets in [`NCKey`] at rest,
/// such that no key can be directly read out from memory. The memory fragments
/// of the key provider will be rotated continuously while not in use.
#[derive(GuardDebug)]
pub struct KeyProvider {
    inner: engine::vault::NCKey<Provider>,
}

impl TryFrom<Vec<u8>> for KeyProvider {
    type Error = MemoryError;

    fn try_from(data: Vec<u8>) -> Result<Self, MemoryError> {
        match NCKey::load(data) {
            Some(inner) => Ok(Self { inner }),
            None => Err(MemoryError::NCSizeNotAllowed),
        }
    }
}

/// Constructor functions for KeyProvider
impl KeyProvider {
    /// Creates a new [`KeyProvider`] with a `passphrase` of arbitrary length.
    ///
    /// The `passphrase` will be truncated to 32 bytes of length internally. This function
    /// is being provided to support legacy passphrase unlock of the snapshot-file.
    ///
    /// # Example
    /// ```
    /// use iota_stronghold::KeyProvider;
    /// use std::ops::Deref;
    ///
    /// let passphrase = b"superlongpassphraseextrasecure";
    /// let mut expected: [u8; 32] = [0u8; 32];
    /// passphrase
    ///     .as_ref()
    ///     .iter()
    ///     .enumerate()
    ///     .take(32)
    ///     .for_each(|(i, value)| {
    ///         expected[i] = *value;
    ///     });
    ///
    /// let result = KeyProvider::with_passphrase_truncated(passphrase.clone());
    /// assert!(result.is_ok());
    ///
    /// // it is safe to unwrap keyprovider
    /// let keyprovider = result.unwrap();
    ///
    /// let buffer = keyprovider.try_unlock();
    /// assert!(buffer.is_ok(), "Unlocking the keyprovider failed");
    ///
    /// // it is safe to unwrap buffer
    /// let buffer = buffer.unwrap();
    /// let buffer_ref = buffer.borrow();
    /// let key = buffer_ref.deref();
    ///
    /// assert_eq!(key, expected, "Key does not match expected {:?}", key);
    /// ```
    pub fn with_passphrase_truncated<P>(mut passphrase: P) -> Result<Self, ClientError>
    where
        P: AsRef<[u8]> + Zeroize,
    {
        let mut key: [u8; KEY_SIZE_HASHED] = [0u8; KEY_SIZE_HASHED];
        passphrase
            .as_ref()
            .iter()
            .enumerate()
            .take(KEY_SIZE_HASHED)
            .for_each(|(i, value)| {
                key[i] = *value;
            });

        let result = Self::try_from(key.to_vec()).map_err(|e| ClientError::Inner(e.to_string()));
        key.zeroize();
        passphrase.zeroize();

        result
    }

    /// Creates a new [`KeyProvider`] from a passphrase, that will be hashed by a custom supplied hashing
    /// function that implements [`Digest`].
    ///
    /// # Example
    /// ```
    /// use crypto::hashes::Digest;
    /// use iota_stronghold::KeyProvider;
    /// use std::ops::Deref;
    ///
    /// // some password and some associated salt.
    /// let mut passphrase = b"passphrase".to_vec();
    ///
    /// // some expected value for the test
    /// let mut blake2b = crypto::hashes::blake2b::Blake2b256::new();
    /// blake2b.update(&passphrase);
    /// let expected = blake2b.finalize();
    ///
    /// // create the keyprovider
    /// let result =
    ///     KeyProvider::with_passphrase_hashed(passphrase, crypto::hashes::blake2b::Blake2b256::new());
    ///
    /// assert!(result.is_ok(), "Failed: {:?}", result);
    ///
    /// // unwrapping the keyprovider is safe here
    /// let keyprovider = result.unwrap();
    ///
    /// // unlock the keyprovider
    /// let buffer = keyprovider.try_unlock();
    ///
    /// assert!(
    ///     buffer.is_ok(),
    ///     "unlocking the inner buffer failed {:?}",
    ///     buffer
    /// );
    ///
    /// // unwrappeing the buffer is safe here
    /// let buffer = buffer.unwrap();
    ///
    /// // borrow the inner key
    /// let buffer_ref = buffer.borrow();
    ///
    /// // deref the key
    /// let key = buffer_ref.deref();
    ///
    /// assert_eq!(key, &expected.to_vec());
    /// ```
    pub fn with_passphrase_hashed<P, D>(mut passphrase: P, mut digest: D) -> Result<Self, ClientError>
    where
        P: AsRef<[u8]> + Zeroize,
        D: Digest,
    {
        digest.update(passphrase.as_ref());
        let key = digest.finalize().to_vec();

        if key.len() != KEY_SIZE_HASHED {
            // This restriction refers to the current implementation of the non-contiguous types
            // and may be lifted in the future. This error will only be thrown, if digests will return
            // another size than 32 bytes.
            return Err(ClientError::IllegalKeySize(32));
        }
        let result = Self::try_from(key).map_err(|e| ClientError::Inner(e.to_string()));
        passphrase.zeroize();

        result
    }

    /// Creates a new [`KeyProvider`] from a passphrase, that will be hashed by `blake2b`.
    ///
    /// # Example
    /// ```
    /// use crypto::hashes::Digest;
    /// use iota_stronghold::KeyProvider;
    /// use std::ops::Deref;
    ///
    /// // some password and some associated salt.
    /// let mut passphrase = b"passphrase".to_vec();
    ///
    /// // some expected value for the test
    /// let mut blake2b = crypto::hashes::blake2b::Blake2b256::new();
    /// blake2b.update(&passphrase);
    /// let expected = blake2b.finalize();
    ///
    /// // create the keyprovider
    /// let result = KeyProvider::with_passphrase_hashed_blake2b(passphrase);
    ///
    /// assert!(result.is_ok(), "Failed: {:?}", result);
    ///
    /// // unwrapping the keyprovider is safe here
    /// let keyprovider = result.unwrap();
    ///
    /// // unlock the keyprovider
    /// let buffer = keyprovider.try_unlock();
    ///
    /// assert!(
    ///     buffer.is_ok(),
    ///     "unlocking the inner buffer failed {:?}",
    ///     buffer
    /// );
    ///
    /// // unwrapping the buffer is safe here
    /// let buffer = buffer.unwrap();
    ///
    /// // borrow the inner key
    /// let buffer_ref = buffer.borrow();
    ///
    /// // deref the key
    /// let key = buffer_ref.deref();
    ///
    /// assert_eq!(key, &expected.to_vec());
    /// ```
    pub fn with_passphrase_hashed_blake2b<P>(passphrase: P) -> Result<Self, ClientError>
    where
        P: AsRef<[u8]> + Zeroize,
    {
        Self::with_passphrase_hashed(passphrase, crypto::hashes::blake2b::Blake2b256::new())
    }

    /// Creates a new [``KeyProvider] from a passphrase, that will be hashed with `argon2`.
    ///
    /// # Example
    /// ```no_run
    /// use iota_stronghold::KeyProvider;
    /// use std::ops::Deref;
    ///
    /// // some password and some associated salt.
    /// let mut passphrase = b"passphrase".to_vec();
    /// let mut salt = b"saltyvalue".to_vec();
    ///
    /// // some expected value for the test
    /// let config = argon2::Config::default();
    /// let expected = argon2::hash_raw(&passphrase, &salt, &config).expect("Failed to calculate hash");
    ///
    /// // create the keyprovider
    /// let result = KeyProvider::with_passphrase_hashed_argon2(passphrase, salt);
    ///
    /// assert!(result.is_ok(), "Failed: {:?}", result);
    ///
    /// // unwrapping the keyprovider is safe here
    /// let keyprovider = result.unwrap();
    ///
    /// // unlock the keyprovider
    /// let buffer = keyprovider.try_unlock();
    ///
    /// assert!(
    ///     buffer.is_ok(),
    ///     "unlocking the inner buffer failed {:?}",
    ///     buffer
    /// );
    ///
    /// // unwrappeing the buffer is safe here
    /// let buffer = buffer.unwrap();
    ///
    /// // borrow the inner key
    /// let buffer_ref = buffer.borrow();
    ///
    /// // deref the key
    /// let key = buffer_ref.deref();
    ///
    /// assert_eq!(key, expected);
    /// ```
    pub fn with_passphrase_hashed_argon2<P>(mut passphrase: P, mut salt: P) -> Result<Self, ClientError>
    where
        P: AsRef<[u8]> + Zeroize,
    {
        let config = argon2::Config::default();

        let key = argon2::hash_raw(passphrase.as_ref(), salt.as_ref(), &config)
            .map_err(|e| ClientError::Inner(e.to_string()))?;

        let result = Self::try_from(key.to_vec()).map_err(|e| ClientError::Inner(e.to_string()));
        passphrase.zeroize();
        salt.zeroize();

        result
    }
}

impl KeyProvider {
    /// Tries to unlock the inner key and returns it.
    /// If unlocking fails, a [`MemoryError`] will be returned
    /// This operations ensures, that the unlocked key will be fragmented,
    /// when it goes out of scope.
    ///
    /// # Example
    /// ```no_run
    /// use iota_stronghold::KeyProvider;
    /// use std::ops::Deref;
    ///
    /// // crate some key data
    /// let keydata = Vec::from_iter(std::iter::repeat(6).take(32));
    ///
    /// // create the keyprovider
    /// let keyprovider = KeyProvider::try_from(keydata.clone()).expect("Fail to create keyprovider");
    ///
    /// // try to unlock the buffer
    /// let buffer = keyprovider.try_unlock();
    /// assert!(buffer.is_ok());
    ///
    /// // get the inner buffer
    /// let buffer = buffer.expect("Failed to get inner buffer");
    ///
    /// // get the inner reference of the buffer
    /// let buffer_ref = buffer.borrow();
    ///
    /// // deref the inner key
    /// let inner_key = buffer_ref.deref();
    /// assert_eq!(keydata, inner_key.to_vec());
    /// ```
    pub fn try_unlock(&self) -> Result<Buffer<u8>, MemoryError> {
        match self.inner.key.unlock() {
            Ok(inner) => Ok(inner),
            Err(memerror) => Err(memerror),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_keyprovider_create() {
        let keydata = Vec::from_iter(std::iter::repeat(6).take(32));
        assert!(KeyProvider::try_from(keydata).is_ok());
    }

    #[test]
    fn test_keyprovider_get() {
        let keydata = Vec::from_iter(std::iter::repeat(6).take(32));
        let keyprovider = KeyProvider::try_from(keydata.clone()).expect("Fail to create keyprovider");

        let buffer = keyprovider.try_unlock();
        assert!(buffer.is_ok());

        let buffer = buffer.expect("Failed to get inner buffer");
        let buffer_ref = buffer.borrow();
        let inner_key = buffer_ref.deref();

        assert_eq!(keydata, inner_key.to_vec());
    }
}
