// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::memories::buffer::Buffer;
use serde::{Deserialize, Serialize};
use std::{
    convert::TryFrom,
    fmt::Debug,
    hash::{Hash, Hasher},
    marker::PhantomData,
};
use zeroize::Zeroize;

/// A provider interface between the vault and a crypto box. See libsodium's [secretbox](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretbox) for an example.
pub trait BoxProvider: 'static + Sized + Ord + PartialOrd + Zeroize + Clone {
    type Error: Debug;

    /// defines the key length for the [`BoxProvider`].
    fn box_key_len() -> usize;
    /// defines the size of the Nonce combined with the Ad for the [`BoxProvider`].
    fn box_overhead() -> usize;

    /// seals some data into the crypto box using the [`Key`] and the associated data.
    fn box_seal(key: &Key<Self>, ad: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// opens a crypto box to get data using the [`Key`] and the associated data.
    fn box_open(key: &Key<Self>, ad: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// fills a buffer [`&mut [u8]`] with secure random bytes.
    fn random_buf(buf: &mut [u8]) -> Result<(), Self::Error>;

    /// creates a vector with secure random bytes based off of an inputted [`usize`] length.
    fn random_vec(len: usize) -> Result<Vec<u8>, Self::Error> {
        let mut buf = vec![0; len];
        Self::random_buf(&mut buf)?;
        Ok(buf)
    }
}

/// A key to the crypto box.  [`Key`] is stored on the heap which makes it easier to erase. Makes use of the
/// [`Buffer<u8>`] type to protect the data.
#[derive(Serialize, Deserialize)]
pub struct Key<T: BoxProvider> {
    /// the guarded raw bytes that make up the key
    pub key: Buffer<u8>,

    /// phantom data to call to the provider.
    #[serde(skip_serializing, skip_deserializing)]
    _box_provider: PhantomData<T>,
}

impl<T: BoxProvider> Key<T> {
    /// generate a random key using secure random bytes
    pub fn random() -> Self {
        Self {
            key: Buffer::alloc(
                T::random_vec(T::box_key_len())
                    .expect("failed to generate random key")
                    .as_slice(),
                T::box_key_len(),
            ),
            _box_provider: PhantomData,
        }
    }

    /// attempts to load a key from inputted data
    ///
    /// Return `None` if the key length doesn't match [`BoxProvider::box_key_len`].
    #[allow(dead_code)]
    pub fn load(key: Vec<u8>) -> Option<Self> {
        if key.len() == T::box_key_len() {
            Some(Self {
                key: Buffer::alloc(key.as_slice(), T::box_key_len()),
                _box_provider: PhantomData,
            })
        } else {
            None
        }
    }

    /// get the key's bytes from the [`Buffer`]
    pub fn bytes(&self) -> Vec<u8> {
        // hacks the guarded type.  Probably not the best solution.
        (*self.key.borrow()).to_vec()
    }
}

impl<T: BoxProvider> Zeroize for Key<T> {
    fn zeroize(&mut self) {
        self.key.zeroize()
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
        Some(self.cmp(other))
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
    fn encrypt<B: BoxProvider, AD: AsRef<[u8]>>(&self, key: &Key<B>, ad: AD) -> Result<T, B::Error> {
        let sealed = B::box_seal(key, ad.as_ref(), self.as_ref())?;
        Ok(T::from(sealed))
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum DecryptError<E: Debug> {
    Invalid,
    Provider(E),
}

/// Trait for decryptable data. Allows the data to be decrypted.
pub trait Decrypt<T: TryFrom<Vec<u8>>>: AsRef<[u8]> {
    /// decrypts raw data and creates a new type T from the plaintext
    fn decrypt<P: BoxProvider, AD: AsRef<[u8]>>(&self, key: &Key<P>, ad: AD) -> Result<T, DecryptError<P::Error>> {
        let opened = P::box_open(key, ad.as_ref(), self.as_ref()).map_err(DecryptError::Provider)?;
        T::try_from(opened).map_err(|_| DecryptError::Invalid)
    }
}
