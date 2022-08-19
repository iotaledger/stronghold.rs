// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::stm::error::TxError;
use std::{
    fmt::Debug,
    hash::{Hash, Hasher},
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

#[derive(Debug)]
pub struct TVar<T>
where
    T: Clone + Debug,
{
    // TODO can be improved with a spinlock?
    pub(crate) data: Arc<Mutex<TVarData<T>>>,
}

// /// A TVar locked by a mutex.
// pub(crate) struct TVarLock<T>
// where T: Clone {
//     pub lock: Mutex<TVarData<T>>
// }

#[derive(Clone, Debug)]
pub(crate) struct TVarData<T>
where
    T: Clone + Debug,
{
    pub value: T,
    pub version: usize,
}

impl<T> TVar<T>
where
    T: Clone + Debug,
{
    pub fn new(value: T, version: usize) -> Self {
        TVar {
            data: Arc::new(Mutex::new(TVarData { value, version })),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn lock(&self) -> MutexGuard<'_, TVarData<T>> {
        self.data.lock().expect("TVar mutex poisoned")
    }

    pub(crate) fn try_lock(&self) -> Result<MutexGuard<'_, TVarData<T>>, TxError> {
        self.data.try_lock().map_err(|_| TxError::LockPresent)
    }

    pub(crate) fn bounded_lock(&self) -> Result<MutexGuard<'_, TVarData<T>>, TxError> {
        // We try to acquire the lock during 1s
        let bound = 1000;
        for _ in 0..bound {
            let lock = self.try_lock();
            if lock.is_ok() {
                return lock;
            }

            // Safe some cpu time.
            std::thread::sleep(Duration::from_millis(1));

            // indicate spin lock to the cpu
            std::hint::spin_loop();
        }
        Err(TxError::TransactionLocked)
    }

    // Get data without holding the mutex
    pub fn try_get_data(&self) -> Result<T, TxError> {
        self.try_lock().map(|guard| guard.value.clone())
    }

    pub fn try_get_version(&self) -> Result<usize, TxError> {
        self.try_lock().map(|guard| guard.version)
    }
}

impl<T> Clone for TVar<T>
where
    T: Clone + Debug,
{
    fn clone(&self) -> Self {
        TVar {
            data: self.data.clone(),
        }
    }
}

impl<T> Hash for TVar<T>
where
    T: Clone + Debug,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Due to API limitations, we cannot return the address of the object itself,
        // but has it in order to have some unique value to be stored inside the hashmap.
        let addr = std::ptr::addr_of!(*self.data) as usize;
        addr.hash(state);
    }
}

impl<T> PartialEq for TVar<T>
where
    T: Clone + Debug,
{
    fn eq(&self, other: &Self) -> bool {
        let a = std::ptr::addr_of!(*self.data) as usize;
        let b = std::ptr::addr_of!(*other.data) as usize;

        a == b
    }
}

impl<T> Eq for TVar<T> where T: Clone + Debug {}

#[cfg(test)]
mod tests {
    use super::TVar;
    use std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
    };

    #[test]
    fn test_tvar_clone_equality() {
        fn calculate_hash<T: Hash>(t: &T) -> u64 {
            let mut s = DefaultHasher::new();
            t.hash(&mut s);
            s.finish()
        }

        let a = TVar::new(10usize, 0);
        let b = a.clone();
        let ha = calculate_hash(&a);
        let hb = calculate_hash(&b);

        assert_eq!(a, b);
        assert_eq!(ha, hb);
    }
}
