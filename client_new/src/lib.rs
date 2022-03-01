// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! # Stronghold Client Interface

#![allow(unused_variables, unused_imports, dead_code)]

#[cfg(feature = "std")]
pub use stronghold_std::*;

#[cfg(feature = "std")]
mod stronghold_std {

    use rlu::{RLUObject, RLUVar, Read, RluContext, Write, RLU};
    use std::{collections::HashMap, error::Error, hash::Hash, path::Path, sync::Arc};

    pub type Result<T> = core::result::Result<T, Box<dyn Error>>;

    pub struct Client {
        store: Option<Arc<Store>>,
        vault: Option<Arc<Vault>>,
    }

    pub struct Store {}

    pub struct Vault {}

    pub struct Snapshot {}

    impl Store {
        pub async fn write(&self, payload: Vec<u8>) {
            todo!()
        }

        pub async fn read(&self) -> Option<Vec<u8>> {
            todo!()
        }
    }

    impl Snapshot {
        pub async fn named(name: String) {
            todo!()
        }

        pub async fn path<P>(path: P) -> Self
        where
            P: AsRef<Path>,
        {
            todo!()
        }
    }

    impl Client {
        /// Returns ok, if a vault exists
        pub async fn check_vault(&self) -> Result<()> {
            todo!()
        }

        /// Returns Ok, if the record exists
        pub async fn check_record(&self) -> Result<()> {
            todo!()
        }
    }

    impl Vault {
        pub async fn write_secret(&self, location: Vec<u8>, payload: Vec<u8>, hint: Vec<u8>) {
            todo!()
        }

        pub async fn delete_secret(&self, location: Vec<u8>) {
            todo!()
        }

        pub async fn revoke_secret(&self, location: Vec<u8>) {
            todo!()
        }

        pub async fn garbage_collect(&self) {
            todo!()
        }

        pub async fn execute_procedure() -> Result<()> {
            todo!()
        }
    }

    // type integration

    /// Prototypical (LRU) cache impl
    pub struct Cache<K, V>
    where
        K: Eq + Clone,
        V: Clone,
    {
        inner: RLUObject<HashMap<K, RLUObject<V>>>,
    }

    impl<K, V> Clone for Cache<K, V>
    where
        K: Eq + Hash + Clone,
        V: Clone,
    {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
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
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests;
