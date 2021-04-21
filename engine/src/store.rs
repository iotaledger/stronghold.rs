// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! This crate contains a key/value cache for the stronghold engine. Data is stored in key-value pairs and an
//! expiration timestamp can be set.  The data is stored in a structured format and can be quickly retrieved at will.
//! Along with the Vault, this crate is used to store general unencrypted data.

mod macros;
mod storage;

pub use self::storage::cache::Cache;
