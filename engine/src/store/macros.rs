// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/// A macro for defining functions whose return values will wrapped in a [`Cache`][super::Cache].
///
/// # Example
/// ```
/// use engine::cache;
///
/// cache! {
///    fn fib(n: u32) -> u32 => {
///      match n {
///         0 => 1,
///         1 => 1,
///         _ => fib(n - 1) + fib(n - 2),
///      }
///    }
/// }
///
/// assert_eq!(fib(20), 10946);
/// assert_eq!(FIB_CACHE.lock().unwrap().get(&20), Some(&10946));
/// ```
#[macro_export]
macro_rules! cache {
    (fn $name:ident ($($arg:ident: $arg_type:ty), *) -> $ret:ty => $body:expr) => {
        use once_cell::sync::Lazy;
        use std::sync::Mutex;
        use engine::store::Cache;
        use paste::paste;

        paste! {
            // create a static instance of `Cache<K, V>` for the expression called `$EXPR_NAME_CACHE`.
            static [<$name:upper _CACHE>]: Lazy<Mutex<Cache<($($arg_type),*), $ret>>> = Lazy::new(|| Mutex::new(Cache::new()));

            #[allow(unused_parens)]
            fn $name($($arg: $arg_type), *) -> $ret {
                // create a static instance of `Cache<K, V>`
                // static CACHE: Lazy<Mutex<Cache<($($arg_type),*), $ret>>> =
                //     Lazy::new(|| Mutex::new(Cache::new()));

                // create key out of arg.
                let key = ($($arg.clone()), *);

                // get mutex to check for cached value.
                let cache = [<$name:upper _CACHE>].lock().unwrap();

                // check for cached value.
                match cache.get(&key) {
                    // if value is cached, return it.
                    Some(val) => val.clone(),
                    None => {
                        // drop the mutex before execution to avoid a deadlock.
                        drop(cache);
                        // execute the body of the function/expression.
                        let value = (||$body)();

                        // re-get mutex to add/update the cache.
                        let mut cache = [<$name:upper _CACHE>].lock().unwrap();
                        cache.insert(key, value, None);
                        value.clone()
                    }
                }
            }
        }
    };
}
