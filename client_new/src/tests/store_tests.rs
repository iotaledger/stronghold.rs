// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{ClientError, Store};

#[test]
fn test_insert_into_store() {
    let store = Store::default();
    let key = b"some key".to_vec();
    let data = b"some data".to_vec();

    assert!(store.insert(key, data, None).is_ok());
}

#[test]
fn test_get_from_store() -> Result<(), ClientError> {
    let store = Store::default();
    let key = b"some key".to_vec();
    let data = b"some data".to_vec();

    assert!(store.insert(key.clone(), data, None).is_ok());
    assert!(store.get(key.clone()).is_ok());
    assert!(store.get(key)?.deref().is_some());

    Ok(())
}

#[test]
fn test_delete_from_store() -> Result<(), ClientError> {
    let store = Store::default();
    let key = b"some key".to_vec();
    let data = b"some data".to_vec();

    store.insert(key.clone(), data, None)?;
    let deleted = store.delete(key.clone());
    assert!(deleted.is_ok());
    assert!(store.get(key)?.deref().is_none());

    Ok(())
}
