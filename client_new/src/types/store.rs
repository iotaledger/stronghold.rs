// Copyright 2020-2021 IOTA Stiftung
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
use serde::{Deserialize, Serialize};

/// The [`StoreGuard`] wraps the [`RwLocKReadGuard`] with an associated key. The
/// inner value can simply be accessed by a custom `deref` function
pub struct StoreGuard<'a> {
    inner: RwLockReadGuard<'a, Cache<Vec<u8>, Vec<u8>>>,
    key: Vec<u8>,
}

impl<'a> StoreGuard<'a> {
    fn from(inner: RwLockReadGuard<'a, Cache<Vec<u8>, Vec<u8>>>, key: Vec<u8>) -> Self {
        Self { inner, key }
    }
}

impl<'a> StoreGuard<'a> {
    pub fn deref(&self) -> Option<&Vec<u8>> {
        let data = self.inner.deref();
        data.get(&self.key)
    }
}

pub struct Store {
    cache: Arc<RwLock<Cache<Vec<u8>, Vec<u8>>>>,
}

impl Default for Store {
    fn default() -> Self {
        Self {
            cache: Arc::new(RwLock::new(Cache::default())),
        }
    }
}

impl Clone for Store {
    fn clone(&self) -> Self {
        let cloned = self.cache.read().expect("").clone();

        Self {
            cache: Arc::new(RwLock::new(cloned)),
        }
    }
}

impl Store {
    /// Inserts a `value` into the store with `key`
    ///
    /// # Example
    /// ```no_run
    /// use iota_stronghold_new::Store;
    ///
    /// let store = Store::default();
    /// let key = b"some key".to_vec();
    /// let data = b"some data".to_vec();
    /// assert!(store.insert(key.clone(), data, None).is_ok());
    /// ```
    pub fn insert(&self, key: Vec<u8>, value: Vec<u8>, lifetime: Option<Duration>) -> Result<(), ClientError> {
        let mut guard = self.cache.try_write().map_err(|_| ClientError::LockAcquireFailed)?;
        guard.insert(key, value, lifetime);

        Ok(())
    }

    /// Tries to get the stored value via `key`
    ///
    /// # Example
    /// ```no_run
    /// use iota_stronghold_new::Store;
    ///
    /// let store = Store::default();
    /// let key = b"some key".to_vec();
    /// let data = b"some data".to_vec();
    /// assert!(store.insert(key.clone(), data, None).is_ok());
    /// assert!(store.get(key.clone()).is_ok());
    /// assert!(store.get(key).unwrap().deref().is_some());
    /// ```
    pub fn get(&self, key: Vec<u8>) -> Result<StoreGuard<'_>, ClientError> {
        let guard = self.cache.try_read().map_err(|_| ClientError::LockAcquireFailed)?;

        // Problem: The returned rwread guard is local to this function, hence we can't return a borrowed ref
        // to the inner value. we could return the guard itself, but would rely on the user to deref the rwguard
        // and then access the value again
        Ok(StoreGuard::from(guard, key))
    }

    /// Tries to delete the inner vale with `key`
    ///
    /// # Example
    /// ```no_run
    /// use iota_stronghold_new::Store;
    ///
    /// let store = Store::default();
    /// let key = b"some key".to_vec();
    /// let data = b"some data".to_vec();
    /// store.insert(key.clone(), data, None)?;
    /// let deleted = store.delete(key.clone());
    /// assert!(deleted.is_ok());
    /// assert!(store.get(key)?.deref().is_none());
    /// ```
    pub fn delete(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>, ClientError> {
        let mut guard = self.cache.try_write().map_err(|_| ClientError::LockAcquireFailed)?;
        Ok(guard.remove(&key))
    }

    /// Checks the [`Store`], if the provided key exists
    /// # Example
    /// ```
    /// use iota_stronghold_new::Store;
    ///
    /// let store = Store::default();
    /// let key = b"some key".to_vec();
    /// let data = b"some data".to_vec();
    /// store.insert(key.clone(), data, None).unwrap();
    /// assert!(store.contains_key(key).unwrap());
    /// ```
    pub fn contains_key(&self, key: Vec<u8>) -> Result<bool, ClientError> {
        let guard = self.cache.try_read().map_err(|_| ClientError::LockAcquireFailed)?;
        Ok(guard.get(&key).is_some())
    }

    /// Returns an clone of inner cache of [`Self`]
    pub(crate) fn atomic_ref(&self) -> Self {
        Self {
            cache: self.cache.clone(),
        }
    }

    /// Reloads the [`Store`] with a given [`Cache`]
    ///
    /// # Examples
    /// ```
    /// use iota_stronghold_new;
    ///
    /// let store = Store::default();
    /// let cache = Cache::new(),
    /// store.reload(cache);
    /// ```
    pub fn reload(&self, cache: Cache<Vec<u8>, Vec<u8>>) -> Result<(), ClientError> {
        let mut inner = self.cache.try_write().map_err(|_| ClientError::LockAcquireFailed)?;
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
        todo!()
    }
}

impl<'a> Deserialize<'a> for Store {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        todo!()
    }
}
