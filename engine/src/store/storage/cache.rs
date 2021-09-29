// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::store::storage::Value;

use serde::{Deserialize, Serialize};

use std::{
    collections::{hash_map::Entry, HashMap},
    fmt::Debug,
    hash::Hash,
    time::{Duration, SystemTime},
};

/// The [`Cache`] struct used to store the data in an ordered format.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Cache<K, V>
where
    K: Hash + Eq,
    V: Clone + Debug,
{
    // hashmap of data.
    table: HashMap<K, Value<V>>,
    // the scan frequency for removing data based on the expiration time.
    scan_freq: Option<Duration>,
    // a created at timestamp.
    created_at: SystemTime,
    // a last scan timestamp.
    last_scan_at: Option<SystemTime>,
}

impl<K: Hash + Eq, V: Clone + Debug> Cache<K, V> {
    /// creates a new empty [`Cache`]
    /// # Example
    /// ```
    /// use engine::store::Cache;
    /// use std::time::Duration;
    ///
    /// let mut cache = Cache::new();
    ///
    /// let key: Vec<u8> = b"key".to_vec();
    /// let value: Vec<u8> = b"value".to_vec();
    ///
    /// cache.insert(key.clone(), value.clone(), None);
    ///
    /// assert_eq!(cache.get(&key), Some(&value))
    /// ```
    pub fn new() -> Self {
        Self {
            table: HashMap::new(),
            scan_freq: None,
            created_at: SystemTime::now(),
            last_scan_at: None,
        }
    }

    /// merges this store with another. This operation consumes the
    /// the [`Cache`]
    /// #Example
    /// ```
    /// use engine::store::Cache;
    /// use std::time::Duration;
    ///
    /// let mut a = Cache::new();
    /// let mut b = Cache::new();
    /// let (key_a, value_a): (Vec<u8>, Vec<u8>) = (b"key_a".to_vec(), b"value_a".to_vec());
    /// let (key_b, value_b): (Vec<u8>, Vec<u8>) = (b"key_b".to_vec(), b"value_b".to_vec());
    ///
    /// a.insert(key_a.clone(), value_a.clone(), None);
    /// b.insert(key_b.clone(), value_b.clone(), None);
    ///
    /// let merged = a.merge(b);
    ///
    /// assert_eq!(merged.get(&key_a), Some(&value_a));
    /// assert_eq!(merged.get(&key_b), Some(&value_b));
    /// ```
    pub fn merge(self, other: Self) -> Self {
        let mut output = Self::new();

        output.scan_freq = self.scan_freq;
        output.last_scan_at = self.last_scan_at;
        output.created_at = self.created_at;
        output.table.extend((self.table).into_iter());
        output.table.extend(other.table.into_iter());

        output
    }

    /// creates an empty [`Cache`] with a periodic scanner which identifies expired entries.
    ///
    /// # Example
    /// ```
    /// use engine::store::Cache;
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
            table: HashMap::new(),
            scan_freq: Some(scan_freq),
            created_at: SystemTime::now(),
            last_scan_at: None,
        }
    }

    /// Gets the value associated with the specified key.
    ///
    /// # Example
    /// ```
    /// use engine::store::Cache;
    /// use std::time::Duration;
    ///
    /// let mut cache = Cache::new();
    ///
    /// let key: &'static str = "key";
    /// let value: &'static str = "value";
    ///
    /// cache.insert(key, value, None);
    ///
    /// assert_eq!(cache.get(&key), Some(&value))
    /// ```
    pub fn get(&self, key: &K) -> Option<&V> {
        let now = SystemTime::now();

        self.table
            .get(key)
            .filter(|value| !value.has_expired(now))
            .map(|value| &value.val)
    }

    /// Gets the value associated with the specified key.  If the key could not be found in the [`Cache`], creates and
    /// inserts the value using a specified `func` function. # Example
    /// ```
    /// use engine::store::Cache;
    /// use std::time::Duration;
    ///
    /// let mut cache = Cache::new();
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

        self.try_remove_expired_items(now);

        match self.table.entry(key) {
            Entry::Occupied(mut occ) => {
                if occ.get().has_expired(now) {
                    occ.insert(Value::new(func(), lifetime));
                }

                &occ.into_mut().val
            }
            Entry::Vacant(vac) => &vac.insert(Value::new(func(), lifetime)).val,
        }
    }

    /// Insert a key-value pair into the cache.
    /// If key was not present, a [`None`] is returned, else the value is updated and the old value is returned.  
    ///
    /// # Example
    /// ```
    /// use engine::store::Cache;
    /// use std::time::Duration;
    ///
    /// let mut cache = Cache::new();
    ///
    /// let key: &'static str = "key";
    /// let value: &'static str = "value";
    ///
    /// let insert = cache.insert(key, value, None);
    ///
    /// assert_eq!(cache.get(&key), Some(&value));
    /// assert!(insert.is_none());
    /// ```
    pub fn insert(&mut self, key: K, value: V, lifetime: Option<Duration>) -> Option<V> {
        let now = SystemTime::now();

        self.try_remove_expired_items(now);

        self.table
            .insert(key, Value::new(value, lifetime))
            .filter(|value| !value.has_expired(now))
            .map(|value| value.val)
    }

    /// Removes a key from the cache.  Returns the value from the key if the key existed in the cache.
    ///
    /// # Example
    ///
    /// ```
    /// use engine::store::Cache;
    /// use std::time::Duration;
    ///
    /// let mut cache = Cache::new();
    ///
    /// let key: &'static str = "key";
    /// let value: &'static str = "value";
    ///
    /// let insert = cache.insert(key, value, None);
    /// assert_eq!(cache.remove(&key), Some(value));
    /// assert!(!cache.contains_key(&key));
    /// ```
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let now = SystemTime::now();

        self.try_remove_expired_items(now);

        self.table
            .remove(key)
            .filter(|value| !value.has_expired(now))
            .map(|value| value.val)
    }

    // Check if the [`Cache<K, V>`] contains a specific key.
    pub fn contains_key(&self, key: &K) -> bool {
        let now = SystemTime::now();

        self.table.get(key).filter(|value| !value.has_expired(now)).is_some()
    }

    // Get the last scanned at time.
    pub fn get_last_scanned_at(&self) -> Option<SystemTime> {
        self.last_scan_at
    }

    /// Get the cache's scan frequency.
    ///
    /// # Example
    /// ```
    /// use engine::store::Cache;
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

    /// Clear the stored cache and reset.
    pub fn clear(&mut self) {
        self.table.clear();
        self.scan_freq = None;
        self.created_at = SystemTime::now();
        self.last_scan_at = None;
    }

    /// attempts to remove expired items based on the current system time provided.
    fn try_remove_expired_items(&mut self, now: SystemTime) {
        if let Some(frequency) = self.scan_freq {
            let since = now
                .duration_since(self.last_scan_at.unwrap_or(self.created_at))
                .expect("System time is before the scanned time");

            if since >= frequency {
                self.table.retain(|_, value| !value.has_expired(now));

                self.last_scan_at = Some(now)
            }
        }
    }
}

/// Default implementation for [`Cache<K, V>`]
impl<K: Hash + Eq, V: Clone + Debug> Default for Cache<K, V> {
    fn default() -> Self {
        Cache::new()
    }
}
