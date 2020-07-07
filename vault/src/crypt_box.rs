use std::{convert::TryFrom, marker::PhantomData};

use serde::{Deserialize, Serialize};

// a provider interface between the db and a crypto box. See https://libsodium.gitbook.io/doc/secret-key_cryptography/secretbox
pub trait BoxProvider: Sized {
    // function for the key length of the crypto box
    fn box_key_len() -> usize;
    // gets the crypto box's overhead
    fn box_overhead() -> usize;

    // seals some data into the crypto box
    fn box_seal(key: &Key<Self>, ad: &[u8], data: &[u8]) -> crate::Result<Vec<u8>>;

    // opens a crypto box to get data.
    fn box_open(key: &Key<Self>, ad: &[u8], data: &[u8]) -> crate::Result<Vec<u8>>;

    // fills a buffer with secure random bytes.
    fn random_buf(buf: &mut [u8]) -> crate::Result<()>;
    // creates a vector with secure random bytes base off of the inputted length.
    fn random_vec(len: usize) -> crate::Result<Vec<u8>> {
        let mut buf = vec![0; len];
        Self::random_buf(&mut buf)?;
        Ok(buf)
    }
}

// A key to the crypto box.  Key is stored on the heap which makes it easier to erase.
#[derive(Serialize, Deserialize)]
pub struct Key<T: BoxProvider> {
    // bytes that make up the key
    pub key: Vec<u8>,
    // callback funciton invoked on drop
    #[serde(skip_serializing, skip_deserializing)]
    drop_fn: Option<&'static fn(&mut [u8])>,
    // associated Provider
    _box_provider: PhantomData<T>,
}

impl<T: BoxProvider> Key<T> {
    // generate a random key using secure random bytes
    pub fn random() -> crate::Result<Self> {
        Ok(Self {
            key: T::random_vec(T::box_key_len())?,
            drop_fn: None,
            _box_provider: PhantomData,
        })
    }

    // attempts to load a key from data
    pub fn load(key: Vec<u8>) -> crate::Result<Self> {
        match key {
            key if key.len() != T::box_key_len() => Err(crate::Error::InterfaceError),
            key => Ok(Self {
                key,
                drop_fn: None,
                _box_provider: PhantomData,
            }),
        }
    }

    // set up the on drop hook which will be called if the instance gets dropped
    pub fn on_drop(&mut self, hook: &'static fn(&mut [u8])) {
        self.drop_fn = Some(hook)
    }

    // get the key's bytes
    pub fn bytes(&self) -> &[u8] {
        &self.key
    }
}

impl<T: BoxProvider> Clone for Key<T> {
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone(),
            drop_fn: self.drop_fn,
            _box_provider: PhantomData,
        }
    }
}

impl<T: BoxProvider> Drop for Key<T> {
    fn drop(&mut self) {
        if let Some(hook) = self.drop_fn {
            hook(&mut self.key);
        }
    }
}

// trait for encryptable data
pub trait Encrypt<T: From<Vec<u8>>>: AsRef<[u8]> {
    // encrypts a raw data and creates a type T from the ciphertext
    fn encrypt<B: BoxProvider>(&self, key: &Key<B>, ad: &[u8]) -> crate::Result<T> {
        let sealed = B::box_seal(key, ad, self.as_ref())?;
        Ok(T::from(sealed))
    }
}

// Trait for decryptable data
pub trait Decrypt<E, T: TryFrom<Vec<u8>, Error = E>>: AsRef<[u8]> {
    // decrypts raw data and creates a new type T from the plaintext
    fn decrypt<B: BoxProvider>(&self, key: &Key<B>, ad: &[u8]) -> crate::Result<T> {
        let opened = B::box_open(key, ad, self.as_ref())?;
        Ok(T::try_from(opened)
            .map_err(|_| crate::Error::DatabaseError(String::from("Invalid Entry")))?)
    }
}
