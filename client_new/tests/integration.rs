// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "std")]
mod stronghold_test_std {

    use iota_stronghold_new::Cache;

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
    fn test_cache_remove() {}

    #[test]
    fn test_cache_remove_all() {}

    #[test]
    fn test_cache_modify() {}

    #[test]
    fn test_cache_contains_key() {}

    #[tokio::test]
    async fn test_cache_async() {}
}
