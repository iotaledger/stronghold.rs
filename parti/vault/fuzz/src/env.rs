use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

// macro for lazy static vars.
macro_rules! lazy_static {
    ($init:expr => $type:ty) => {{
        static mut VAL: Option<$type> = None;
        static INIT: std::sync::Once = std::sync::Once::new();

        INIT.call_once(|| unsafe { VAL = Some($init) });
        unsafe { VAL.as_ref() }.expect(line_error!())
    }};
}

// macro for lazy static env vars.
macro_rules! lazy_env {
    ($key:expr, $default:expr => $type:ty) => {
        *lazy_static! {
            std::env::var($key).ok()
                .and_then(|env| std::str::FromStr::from_str(&env).ok())
                .unwrap_or($default)
            => $type
        }
    };
}

// env vars
pub struct Env;

impl Env {
    // input channel for storage worker
    pub fn storage() -> Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>> {
        lazy_static!(
            Arc::new(RwLock::new(HashMap::new())) => Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>>
        )
        .clone()
    }

    // input channel for shadow storage worker
    pub fn shadow_storage() -> Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>> {
        lazy_static!(
            Arc::new(RwLock::new(HashMap::new()))
                => Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>>
        )
        .clone()
    }

    // get amount of clients or the default.
    pub fn client_count() -> usize {
        lazy_env!("CLIENT_COUNT", 30 => usize)
    }

    // get the defined error probability or the default.
    pub fn error_rate() -> usize {
        lazy_env!("ERROR_RATE", 5 => usize)
    }

    // get the verify interval; how many transactions should complete before verification
    pub fn verify_number() -> usize {
        lazy_env!("VERIFY_NUMBER", 155 => usize)
    }

    // get the delay to wait until a transaction is retried.
    pub fn retry_delay() -> u64 {
        lazy_env!("RETRY_DELAY", 52 => u64)
    }
}
