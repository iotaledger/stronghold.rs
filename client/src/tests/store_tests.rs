// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{ClientError, Store};
use stronghold_utils::random as rand;

#[test]
fn test_insert_into_store() {
    let store = Store::default();
    let key = b"some key";
    let data = b"some data".to_vec();

    assert!(store.insert(key.to_vec(), data.clone(), None).is_ok());

    let new_data = b"some_other_data".to_vec();

    let previous = store.insert(key.to_vec(), new_data, None).unwrap();
    assert!(previous.is_some());
    assert_eq!(previous.unwrap(), data);
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

#[test]
fn test_keys() {
    let store = Store::default();
    let max_entries = 10;
    let generate = || -> Vec<Vec<u8>> {
        std::iter::repeat_with(|| rand::variable_bytestring(256))
            .take(max_entries)
            .collect()
    };

    let mut keys = generate();
    let values = generate();

    for (key, value) in keys.clone().into_iter().zip(values.into_iter()) {
        assert!(store.insert(key, value, None).is_ok());
    }
    let result = store.keys();
    assert!(result.is_ok());

    let mut actual = result.unwrap();
    actual.sort();
    keys.sort();

    assert_eq!(actual, keys);
}

use threadpool::ThreadPool;
#[test]
fn test_multithreaded() {
    let main_store = Store::default();
    const NB_INPUTS: usize = 10;
    let generate = || -> Vec<Vec<u8>> {
        std::iter::repeat_with(|| rand::variable_bytestring(256))
            .take(NB_INPUTS)
            .collect()
    };

    let mut main_keys = generate();
    let keys = main_keys.clone();
    let main_values = generate();
    let values = main_values.clone();

    let pool = ThreadPool::new(8);
    for (key, value) in keys.into_iter().zip(values.into_iter()) {
        let store = main_store.clone();
        pool.execute(move || {
            assert!(store.insert(key, value, None).is_ok());
        });
    }
    pool.join();

    let result = main_store.keys();
    assert!(result.is_ok());

    let mut actual = result.unwrap();
    actual.sort();
    main_keys.sort();

    assert_eq!(actual, main_keys);

}
