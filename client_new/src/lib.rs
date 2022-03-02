// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! # Stronghold Client Interface

#![allow(unused_variables, unused_imports, dead_code)]

#[cfg(feature = "std")]
pub use stronghold_std::*;

#[cfg(feature = "std")]
mod stronghold_std {

    pub use crate::types::*;
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
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests;

#[cfg(feature = "std")]
pub mod types;
