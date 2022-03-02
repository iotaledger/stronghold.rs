// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::Result;
use std::{
    collections::HashMap,
    hash::Hash,
    sync::Arc,
    time::{Duration, SystemTime},
};

// This module should potentially be moved to `runtime`
use rlu::{RLUObject, RLUVar, Read, RluContext, Write, RLU};
use serde::{Deserialize, Serialize};

pub struct Cache<K, V>
where
    K: Eq + Clone,
    V: Clone,
{
    // the inner tabled data
    inner: RLUObject<HashMap<K, RLUObject<V>>>,
    // the scan frequency for removing data based on the expiration time.
    scan_freq: Option<Duration>,
    // a created at timestamp.
    created_at: SystemTime,
    // a last scan timestamp.
    last_scan_at: Option<SystemTime>,
}

impl<K, V> Clone for Cache<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            scan_freq: self.scan_freq,
            created_at: self.created_at,
            last_scan_at: self.last_scan_at,
        }
    }
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
    pub fn insert(&self, key: K, value: V) -> Result<()> {
        let tvar = self.inner.var();

        Ok(self.inner.ctrl().execute(move |mut ctx| {
            let key = key.clone();
            let value = value.clone();

            let mut var = ctx.get_mut(&tvar)?;
            (*var).insert(key, value.into());
            Ok(())
        })?)
    }

    pub fn get(&self, key: &K) -> Option<Arc<RLUVar<V>>> {
        let tvar = self.inner.var();
        let map = tvar.get();

        if let Some(inner) = map.get(key) {
            return Some(inner.var());
        }

        None
    }

    pub fn modify(&self, key: &K, value: V) -> Result<()> {
        let tvar = self.inner.var();
        let map = tvar.get();

        if let Some(inner) = map.get(key) {
            let inner_tvar = inner.var();
            inner.ctrl().execute(|mut ctx| {
                let mut guard = ctx.get_mut(&inner_tvar)?;
                *guard = value.clone();

                Ok(())
            })?;
        }
        Ok(())
    }

    pub fn delete(&self, key: &K) -> Result<()> {
        let ctrl = self.inner.ctrl();
        let var = self.inner.var();

        Ok(ctrl.execute(|mut ctx| {
            let mut guard = ctx.get_mut(&var)?;
            (*guard).remove(key);

            Ok(())
        })?)
    }

    pub fn delete_all(&self) -> Result<()> {
        let ctrl = self.inner.ctrl();
        let var = self.inner.var();

        Ok(ctrl.execute(|mut ctx| {
            let mut guard = ctx.get_mut(&var)?;
            (*guard).clear();

            Ok(())
        })?)
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
