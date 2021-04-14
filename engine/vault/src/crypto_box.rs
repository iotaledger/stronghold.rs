// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
use std::{
    convert::TryFrom,
    fmt::Debug,
    hash::{Hash, Hasher},
    marker::PhantomData,
};

use runtime::GuardedVec;

use serde::{Deserialize, Serialize};

/// A provider interface between the vault and a crypto box. See libsodium's [secretbox](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretbox) for an example.
pub trait BoxProvider: Sized + Ord + PartialOrd {
    /// function for the key length of the crypto box
    fn box_key_len() -> usize;
    /// gets the crypto box's overhead
    fn box_overhead() -> usize;

    /// seals some data into the crypto box using the `key` and the `ad`
    fn box_seal(key: &Key<Self>, ad: &[u8], data: &[u8]) -> crate::Result<Vec<u8>>;

    /// opens a crypto box to get data using the `key` and the `ad`.
    fn box_open(key: &Key<Self>, ad: &[u8], data: &[u8]) -> crate::Result<Vec<u8>>;

    /// fills a buffer `buf` with secure random bytes.
    fn random_buf(buf: &mut [u8]) -> crate::Result<()>;

    /// creates a vector with secure random bytes based off of an inputted length `len`.
    fn random_vec(len: usize) -> crate::Result<Vec<u8>> {
        let mut buf = vec![0; len];
        Self::random_buf(&mut buf)?;
        Ok(buf)
    }
}

/// A key to the crypto box.  Key is stored on the heap which makes it easier to erase.
#[derive(Serialize, Deserialize)]
pub struct Key<T: BoxProvider> {
    /// the guarded raw bytes that make up the key
    pub key: GuardedVec<u8>,

    #[serde(skip_serializing, skip_deserializing)]
    _box_provider: PhantomData<T>,
}

impl<T: BoxProvider> Key<T> {
    /// generate a random key using secure random bytes
    pub fn random() -> crate::Result<Self> {
        Ok(Self {
            key: GuardedVec::new(T::box_key_len(), |v| {
                v.copy_from_slice(
                    T::random_vec(T::box_key_len())
                        .expect("failed to generate random key")
                        .as_slice(),
                )
            }),

            _box_provider: PhantomData,
        })
    }

    /// attempts to load a key from inputted data
    pub fn load(key: Vec<u8>) -> crate::Result<Self> {
        match key {
            key if key.len() != T::box_key_len() => Err(crate::Error::InterfaceError),
            key => Ok(Self {
                key: GuardedVec::new(T::box_key_len(), |v| v.copy_from_slice(key.as_slice())),
                _box_provider: PhantomData,
            }),
        }
    }

    /// get the key's bytes
    pub fn bytes(&self) -> Vec<u8> {
        // hacks the guarded type.  Probably not the best solution.
        (*self.key.borrow()).to_vec()
    }
}

impl<T: BoxProvider> Clone for Key<T> {
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone(),
            _box_provider: PhantomData,
        }
    }
}

impl<T: BoxProvider> Eq for Key<T> {}

impl<T: BoxProvider> PartialEq for Key<T> {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key && self._box_provider == other._box_provider
    }
}

impl<T: BoxProvider> PartialOrd for Key<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(&other))
    }
}

impl<T: BoxProvider> Ord for Key<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.key.borrow().cmp(&other.key.borrow())
    }
}

impl<T: BoxProvider> Hash for Key<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.key.borrow().hash(state);
        self._box_provider.hash(state);
    }
}

impl<T: BoxProvider> Debug for Key<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyData")
    }
}

/// trait for encryptable data. Allows the data to be encrypted.
pub trait Encrypt<T: From<Vec<u8>>>: AsRef<[u8]> {
    /// encrypts a raw data and creates a type T from the ciphertext
    fn encrypt<B: BoxProvider, AD: AsRef<[u8]>>(&self, key: &Key<B>, ad: AD) -> crate::Result<T> {
        let sealed = B::box_seal(key, ad.as_ref(), self.as_ref())?;
        Ok(T::from(sealed))
    }
}

/// Trait for decryptable data.  Allows the data to be decrypted.
pub trait Decrypt<E, T: TryFrom<Vec<u8>, Error = E>>: AsRef<[u8]> {
    /// decrypts raw data and creates a new type T from the plaintext
    fn decrypt<B: BoxProvider, AD: AsRef<[u8]>>(&self, key: &Key<B>, ad: AD) -> crate::Result<T> {
        let opened = B::box_open(key, ad.as_ref(), self.as_ref())?;
        T::try_from(opened).map_err(|_| crate::Error::DatabaseError(String::from("Invalid Entry")))
    }
}
