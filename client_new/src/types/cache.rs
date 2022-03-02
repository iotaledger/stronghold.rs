// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::Result;
use std::{
    cell::Cell,
    collections::HashMap,
    hash::Hash,
    ops::Deref,
    sync::Arc,
    time::{Duration, SystemTime},
};

use rlu::{RLUObject, RLUVar, Read, RluContext, Write, RLU};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub(crate) struct Value<T>
where
    T: Clone,
{
    // data field.
    pub val: RLUObject<T>,
    // expiration time.
    expiration: Option<SystemTime>,
}

impl<T> Deref for Value<T>
where
    T: Clone,
{
    type Target = RLUObject<T>;

    fn deref(&self) -> &Self::Target {
        &self.val
    }
}

impl<T> Value<T>
where
    T: Clone,
{
    /// Create a new [`Value`] with a specified expiration.
    pub fn new(val: T, duration: Option<Duration>) -> Self {
        Value {
            val: val.into(),
            expiration: duration.map(|d| SystemTime::now() + d),
        }
    }

    /// Checks to see if the [`Value`] has expired.
    pub fn has_expired(&self, time_now: SystemTime) -> bool {
        self.expiration.map_or(false, |time| time_now >= time)
    }
}

/// An evicting cache data structure.
///
/// *NOTE*: this is a port to an RLU based data structure from runtime
#[derive(Clone)]
pub struct Cache<K, V>
where
    K: Eq + Clone,
    V: Clone,
{
    // the inner table data
    inner: RLUObject<HashMap<K, Value<V>>>,
    // the scan frequency for removing data based on the expiration time.
    scan_freq: Option<Duration>,
    // a created at timestamp.
    created_at: SystemTime,
    // a last scan timestamp.
    last_scan_at: Option<SystemTime>,
}

impl<K, V> Default for Cache<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    fn default() -> Self {
        Self {
            inner: HashMap::new().into(),
            scan_freq: None,
            created_at: SystemTime::now(),
            last_scan_at: None,
        }
    }
}

impl<K, V> Cache<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    /// Insert a key-value pair into the cache.
    /// If key was not present, a [`None`] is returned, else the value is updated and the old value is returned.  
    ///
    /// # Example
    /// ```
    /// use iota_stronghold_new::types::Cache;
    /// use std::time::Duration;
    ///
    /// let mut cache = Cache::default();
    ///
    /// let key: &'static str = "key";
    /// let value: &'static str = "value";
    ///
    /// let insert = cache.insert(key, value, None);
    ///
    /// assert_eq!(cache.get(&key), Some(&value));
    /// assert!(insert.unwrap().is_none());
    /// ```
    pub fn insert(&self, key: K, value: V, lifetime: Option<Duration>) -> Result<Option<V>> {
        let tvar = self.inner.var();

        let previous = self.get(&key).cloned();

        self.inner
            .ctrl()
            .execute(move |mut ctx| {
                let key = key.clone();
                let value = value.clone();

                let mut var = ctx.get_mut(tvar)?;

                (*var).insert(key, Value::new(value, lifetime));

                Ok(())
            })
            .map(|_| Option::<V>::None)?;

        Ok(previous)
    }
    /// Gets the value associated with the specified key.
    ///
    /// # Example
    /// ```
    /// use iota_stronghold_new::types::Cache;
    /// use std::time::Duration;
    ///
    /// let mut cache = Cache::default();
    ///
    /// let key: &'static str = "key";
    /// let value: &'static str = "value";
    ///
    /// cache.insert(key, value, None);
    ///
    /// assert_eq!(cache.get(&key), Some(&value))
    /// ```
    pub fn get(&self, key: &K) -> Option<&V> {
        let tvar = self.inner.var();
        let map = tvar.get();

        if let Some(inner) = map.get(key) {
            return Some(inner.var().get());
        }

        None
    }

    /// Modifies the value found at `key`, and replaces it with `value`
    pub fn modify(&self, key: &K, value: V) -> Result<()> {
        let tvar = self.inner.var();
        let map = tvar.get();

        if let Some(inner) = map.get(key) {
            let inner_tvar = inner.var();
            inner.ctrl().execute(|mut ctx| {
                let mut guard = ctx.get_mut(inner_tvar)?;
                *guard = value.clone();

                Ok(())
            })?;
        }
        Ok(())
    }

    /// Gets the value associated with the specified key.  If the key could not be found in the [`Cache`], creates and
    /// inserts the value using a specified `func` function.
    ///
    /// # Example
    /// ```
    /// use iota_stronghold_new::types::Cache;
    /// use std::time::Duration;
    ///
    /// let mut cache = Cache::default();
    ///
    /// let key = "key";
    /// let value = "value";
    ///
    /// assert_eq!(cache.get_or_insert(key, move || value, None), &value);
    /// assert!(cache.contains_key(&key));
    /// ```
    pub fn get_or_insert<F>(&mut self, key: K, func: F, lifetime: Option<Duration>) -> &V
    where
        F: Fn() -> V,
    {
        let now = SystemTime::now();

        // could this be done via entry api
        match self.get(&key) {
            Some(inner) => inner,
            None => {
                self.insert(key.clone(), func(), lifetime).expect("msg");
                self.get(&key).unwrap()
            }
        }
    }

    /// Removes a key from the cache.  Returns the value from the key if the key existed in the cache.
    ///
    /// # Example
    ///
    /// ```
    /// use iota_stronghold_new::types::Cache;
    /// use std::time::Duration;
    ///
    /// let mut cache = Cache::default();
    ///
    /// let key: &'static str = "key";
    /// let value: &'static str = "value";
    ///
    /// let insert = cache.insert(key, value, None);
    /// assert!(cache.remove(&key).is_ok());
    /// assert!(!cache.contains_key(&key));
    /// ```
    pub fn remove(&self, key: &K) -> Result<()> {
        let ctrl = self.inner.ctrl();
        let var = self.inner.var();

        Ok(ctrl.execute(|mut ctx| {
            let mut guard = ctx.get_mut(var)?;
            (*guard).remove(key);

            Ok(())
        })?)
    }

    pub fn remove_all(&self) -> Result<()> {
        let ctrl = self.inner.ctrl();
        let var = self.inner.var();

        Ok(ctrl.execute(|mut ctx| {
            let mut guard = ctx.get_mut(var)?;
            (*guard).clear();

            Ok(())
        })?)
    }

    // Check if the [`Cache<K, V>`] contains a specific key.
    pub fn contains_key(&self, key: &K) -> bool {
        let ctrl = self.inner.ctrl();
        let var = self.inner.var();
        let now = SystemTime::now();
        let result = Cell::new(false);

        ctrl.execute(|ctx| {
            let inner = ctx.get(var);

            result.set(
                (*inner)
                    .as_ref()
                    .unwrap()
                    .get(key)
                    .filter(|value| !value.has_expired(now))
                    .is_some(),
            );
            Ok(())
        })
        .expect(""); // FIXME: Proper Error Type
        result.get()
    }

    // Get the last scanned at time.
    pub fn get_last_scanned_at(&self) -> Option<SystemTime> {
        self.last_scan_at
    }

    /// Get the cache's scan frequency.
    ///
    /// # Example
    /// ```
    /// use iota_stronghold_new::types::Cache;
    /// use std::time::Duration;
    ///
    /// let scan_freq = Duration::from_secs(60);
    ///
    /// let mut cache = Cache::create_with_scanner(scan_freq);
    ///
    /// let key: &'static str = "key";
    /// let value: &'static str = "value";
    ///
    /// cache.insert(key, value, None);
    ///
    /// assert_eq!(cache.get_scan_freq(), Some(scan_freq));
    /// ```
    pub fn get_scan_freq(&self) -> Option<Duration> {
        self.scan_freq
    }

    /// creates an empty [`Cache`] with a periodic scanner which identifies expired entries.
    ///
    /// # Example
    /// ```
    /// use iota_stronghold_new::types::Cache;
    /// use std::time::Duration;
    ///
    /// let scan_freq = Duration::from_secs(60);
    ///
    /// let mut cache = Cache::create_with_scanner(scan_freq);
    ///
    /// let key: &'static str = "key";
    /// let value: &'static str = "value";
    ///
    /// cache.insert(key, value, None);
    ///
    /// assert_eq!(cache.get(&key), Some(&value));
    /// ```
    pub fn create_with_scanner(scan_freq: Duration) -> Self {
        Self {
            inner: HashMap::new().into(),
            scan_freq: Some(scan_freq),
            created_at: SystemTime::now(),
            last_scan_at: None,
        }
    }

    /// attempts to remove expired items based on the current system time provided.
    fn try_remove_expired_items(&mut self, now: SystemTime) {
        // if let Some(frequency) = self.scan_freq {
        //     let since = now
        //         .duration_since(self.last_scan_at.unwrap_or(self.created_at))
        //         .expect("System time is before the scanned time");

        //     if since >= frequency {
        //         self.table.retain(|_, value| !value.has_expired(now));

        //         self.last_scan_at = Some(now)
        //     }
        // }
        todo!()
    }

    /// Clear the stored cache and reset.
    pub fn clear(&mut self) -> Result<()> {
        self.remove_all()?;
        self.scan_freq = None;
        self.created_at = SystemTime::now();
        self.last_scan_at = None;

        Ok(())
    }
}

// Serde implemenation for compatibility
impl<K, V> Serialize for Cache<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        todo!()
    }
}

impl<'a, K, V> Deserialize<'a> for Cache<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        todo!()
    }
}
