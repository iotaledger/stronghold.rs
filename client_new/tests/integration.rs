// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "std")]
mod stronghold_test_std {

    use iota_stronghold_new::{Cache, Result};

    #[test]
    fn test_cache_concurrent() -> Result<()> {
        let cache = Cache::default();
        cache.insert(1223usize, "hello, world")?;

        assert!(cache.get(&1223).is_some());
        assert_eq!(*cache.get(&1223).unwrap().get(), "hello, world");

        Ok(())
    }

    #[tokio::test]
    async fn test_cache_async() {}
}
