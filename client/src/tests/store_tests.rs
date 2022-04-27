// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{ClientError, Store};

#[test]
fn test_insert_into_store() {
    let store = Store::default();
    let key = b"some key";
    let data = b"some data".to_vec();

    assert!(store.insert(key.to_vec(), data, None).is_ok());
}

#[test]
fn test_get_from_store() -> Result<(), ClientError> {
    let store = Store::default();
    let key = b"some key";
    let data = b"some data".to_vec();

    assert!(store.insert(key.to_vec(), data, None).is_ok());
    assert!(store.get(&key.clone()).is_ok());
    assert!(store.get(key)?.is_some());

    Ok(())
}

#[test]
fn test_delete_from_store() -> Result<(), ClientError> {
    let store = Store::default();
    let key = b"some key";
    let data = b"some data".to_vec();

    store.insert(key.to_vec(), data, None)?;
    let deleted = store.delete(&key.clone());
    assert!(deleted.is_ok());
    assert!(store.get(key)?.is_none());

    Ok(())
}

#[test]
fn test_contains_key() -> Result<(), ClientError> {
    let store = Store::default();
    let key = b"some key";
    let data = b"some data".to_vec();
    store.insert(key.to_vec(), data, None)?;
    assert!(store.contains_key(key).unwrap());
    Ok(())
}
