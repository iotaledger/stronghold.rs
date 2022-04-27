// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    error::Error,
    marker::PhantomData,
    ops::Deref,
    sync::{Arc, RwLock, RwLockReadGuard},
    time::Duration,
};

use crate::ClientError;
use engine::store::Cache;
use rlu::Read;
use serde::{de::DeserializeSeed, Deserialize, Serialize};

// The [`StoreGuard`] wraps the [`RwLocKReadGuard`] with an associated key. The
// inner value can simply be accessed by a custom `deref` function
// pub struct StoreGuard<'a> {
//     inner: RwLockReadGuard<'a, Cache<Vec<u8>, Vec<u8>>>,
//     key: Vec<u8>,
// }

// impl<'a> StoreGuard<'a> {
//     fn from(inner: RwLockReadGuard<'a, Cache<Vec<u8>, Vec<u8>>>, key: Vec<u8>) -> Self {
//         Self { inner, key }
//     }
// }

// impl<'a> StoreGuard<'a> {
//     pub fn deref(&self) -> Option<&Vec<u8>> {
//         let data = self.inner.deref();
//         data.get(&self.key)
//     }
// }

#[derive(Clone, Default)]
pub struct Store {
    pub(crate) cache: Arc<RwLock<Cache<Vec<u8>, Vec<u8>>>>,
}

impl Store {
    /// Inserts a `value` into the store with `key`
    ///
    /// # Example
    /// ```ignore
    /// use iota_stronghold::Store;
    ///
    /// let store = Store::default();
    /// let key = b"some key".to_vec();
    /// let data = b"some data".to_vec();
    /// assert!(store.insert(key.clone(), data, None).is_ok());
    /// ```
    pub fn insert(&self, key: Vec<u8>, value: Vec<u8>, lifetime: Option<Duration>) -> Result<(), ClientError> {
        let mut guard = self.cache.try_write()?;
        guard.insert(key.to_vec(), value, lifetime);

        Ok(())
    }

    /// Tries to get the stored value via `key`
    ///
    /// # Example
    /// ```ignore
    /// use iota_stronghold::Store;
    ///
    /// let store = Store::default();
    /// let key = b"some key".to_vec();
    /// let data = b"some data".to_vec();
    /// assert!(store.insert(key.clone(), data, None).is_ok());
    /// assert!(store.get(key.clone()).is_ok());
    /// assert!(store.get(key).unwrap().deref().is_some());
    /// ```
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ClientError> {
        let guard = self.cache.try_read().map_err(|_| ClientError::LockAcquireFailed)?;

        // Problem: The returned rwread guard is local to this function, hence we can't return a borrowed ref
        // to the inner value. we could return the guard itself, but would rely on the user to deref the rwguard
        // and then access the value again
        Ok(guard.get(&key.to_vec()).cloned())
    }

    /// Tries to delete the inner vale with `key`
    ///
    /// # Example
    /// ```ignore
    /// use iota_stronghold::Store;
    ///
    /// let store = Store::default();
    /// let key = b"some key".to_vec();
    /// let data = b"some data".to_vec();
    /// store.insert(key.clone(), data, None).unwrap();
    /// let deleted = store.delete(key.clone());
    /// assert!(deleted.is_ok());
    /// assert!(store.get(key).unwrap().deref().is_none());
    /// ```
    pub fn delete(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ClientError> {
        let mut guard = self.cache.try_write()?;
        Ok(guard.remove(&key.to_vec()))
    }

    /// Checks the [`Store`], if the provided key exists
    /// # Example
    /// ```ignore
    /// use iota_stronghold::Store;
    ///
    /// let store = Store::default();
    /// let key = b"some key".to_vec();
    /// let data = b"some data".to_vec();
    /// store.insert(key.clone(), data, None).unwrap();
    /// assert!(store.contains_key(key).unwrap());
    /// ```
    pub fn contains_key(&self, key: &[u8]) -> Result<bool, ClientError> {
        let guard = self.cache.try_read()?;
        Ok(guard.get(&key.to_vec()).is_some())
    }

    /// Reloads the [`Store`] with a given [`Cache`]
    ///
    /// # Examples
    /// ```
    /// use engine::store::Cache;
    /// use iota_stronghold::Store;
    ///
    /// let store = Store::default();
    /// let cache = Cache::new();
    /// store.reload(cache);
    /// ```
    pub fn reload(&self, cache: Cache<Vec<u8>, Vec<u8>>) -> Result<(), ClientError> {
        let mut inner = self.cache.try_write()?;
        *inner = cache;
        Ok(())
    }
}

// compatibility implementation

impl Serialize for Store {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.cache.serialize(serializer)
    }
}

impl<'a> Deserialize<'a> for Store {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        let cache = Cache::deserialize(deserializer)?;
        Ok(Store {
            cache: Arc::new(RwLock::new(cache)),
        })
    }
}
