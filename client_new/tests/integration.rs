// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "std")]
mod stronghold_test_std {

    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use iota_stronghold_new::Cache;
    use rand_utils::random::{string, usize};

    #[test]
    fn test_cache_insert() {
        let cache = Cache::default();
        assert!(cache.insert(1223usize, "hello, world", None).is_ok());
        assert!(cache.get(&1223).is_some());
        if let Some(inner) = cache.get(&1223) {
            assert_eq!(*inner, "hello, world");
        }
    }

    #[test]
    fn test_cache_remove() {
        let cache = Cache::default();
        for _ in 0..100 {
            let key = usize(usize::MAX);
            let value = string(255);
            assert!(cache.insert(key, value.clone(), None).is_ok());
            assert!(cache.remove(&key).is_ok());
            assert!(cache.get(&key).is_none());
        }
    }

    #[test]
    fn test_cache_remove_all() {
        let cache = Cache::default();
        let mut compare = HashMap::new();

        for _ in 0..100 {
            let key = usize(usize::MAX);
            let value = string(255);
            compare.insert(key, value.clone());

            assert!(cache.insert(key, value.clone(), None).is_ok());
        }

        assert!(cache.remove_all().is_ok());

        for (key, _) in compare {
            assert!(cache.get(&key).is_none())
        }
    }

    #[test]
    fn test_cache_modify() {
        let cache = Cache::default();

        for _ in 0..100 {
            let key = usize(usize::MAX);
            let v1 = string(255);
            let v2 = string(255);
            assert!(cache.insert(key, v1.clone(), None).is_ok());
            assert!(cache.modify(&key, v2.clone()).is_ok());
            assert!(cache.get(&key).is_some());
            assert_eq!(cache.get(&key), Some(&v2));
        }
    }

    #[test]
    fn test_cache_contains_key() {
        let cache = Cache::default();

        for _ in 0..100 {
            let key = usize(usize::MAX);
            let v1 = string(255);
            assert!(cache.insert(key, v1, None).is_ok());
            assert!(cache.contains_key(&key));
        }
    }

    #[ignore]
    #[test]
    fn test_cache_concurrent() {
        use std::thread::spawn;

        let runs = 10;
        let cache = Arc::new(Mutex::new(HashMap::new()));
        let mut threads = Vec::new();

        // writes
        for key in 0..runs {
            let cache = cache.clone();
            threads.push(spawn(move || {
                let v1 = string(255);

                cache.lock().expect("").insert(key, v1);
            }));
        }

        std::thread::sleep(Duration::from_millis(1));

        // reads
        for key in 0..runs {
            let cache = cache.clone();
            threads.push(spawn(move || assert!(cache.lock().expect("").get(&key).is_some())));
        }

        threads.into_iter().for_each(|t| {
            t.join().expect("Could not join");
        });
    }
}
