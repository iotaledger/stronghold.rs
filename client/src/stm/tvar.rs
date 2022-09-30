// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::stm::error::TxError;
use crate::stm::shared_value::*;

use std::{
    fmt::Debug,
    hash::{Hash, Hasher},
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

#[derive(Clone, Debug)]
pub struct TVar {
    pub(crate) data: Arc<Mutex<TVarData>>,
}

#[derive(Clone, Debug)]
pub(crate) struct TVarData {
    pub(crate) value: SharedValue,
    pub(crate) version: usize,
}

impl TVar {
    pub fn new(value: SharedValue, version: usize) -> Self {
        TVar {
            data: Arc::new(Mutex::new(TVarData { value, version })),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn lock(&self) -> MutexGuard<'_, TVarData> {
        self.data.lock().expect("TVar mutex poisoned")
    }

    pub(crate) fn try_lock(&self) -> Result<MutexGuard<'_, TVarData>, TxError> {
        self.data.try_lock().map_err(|_| TxError::LockPresent)
    }

    pub(crate) fn bounded_lock(&self) -> Result<MutexGuard<'_, TVarData>, TxError> {
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
    pub fn try_get_data<T>(&self) -> Result<T, TxError>
    where
        T: TryFrom<SharedValue, Error=TxError> + Clone,
    {
        let guard = self.try_lock()?.clone();
        let data = T::try_from(guard.value)?;
        Ok(data)
    }

    pub fn try_get_version(&self) -> Result<usize, TxError> {
        self.try_lock().map(|guard| guard.version)
    }

    /// Try to consume the `TVar` if it there is a single instance existing
    /// If multiple clones of the `TVar` exists then it fails and returns
    /// an identical `TVar`
    pub fn take<T>(self) -> Result<T, Self>
    where
        T: TryFrom<SharedValue>,
    {
        match Arc::try_unwrap(self.data) {
            Ok(mutex) => {
                let tvar_data = mutex.into_inner().expect("Mutex poisoned when trying to consume it");
                let err_value = tvar_data.clone();
                T::try_from(tvar_data.value).map_err(|_| TVar {
                    data: Arc::new(Mutex::new(err_value)),
                })
            }
            Err(arc) => Err(TVar { data: arc }),
        }
    }
}

impl Hash for TVar {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Due to API limitations, we cannot return the address of the object itself,
        // but has it in order to have some unique value to be stored inside the hashmap.
        let addr = std::ptr::addr_of!(*self.data) as usize;
        addr.hash(state);
    }
}

impl PartialEq for TVar {
    fn eq(&self, other: &Self) -> bool {
        let a = std::ptr::addr_of!(*self.data) as usize;
        let b = std::ptr::addr_of!(*other.data) as usize;

        a == b
    }
}

impl Eq for TVar {}

#[cfg(test)]
mod tests {
    use super::{SharedValue::*, TVar};
    use std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
        thread,
    };

    #[test]
    fn test_tvar_clone_equality() {
        fn calculate_hash<T: Hash>(t: &T) -> u64 {
            let mut s = DefaultHasher::new();
            t.hash(&mut s);
            s.finish()
        }

        let a = TVar::new(SharedUsize(10), 0);
        let b = a.clone();
        let ha = calculate_hash(&a);
        let hb = calculate_hash(&b);

        assert_eq!(a, b);
        assert_eq!(ha, hb);
    }

    #[test]
    fn test_tvar_take() {
        let a = TVar::new(SharedUsize(10), 0);
        let mut handles = vec![];

        for _ in 0..100 {
            let b = a.clone();
            let h = thread::spawn(move || {
                assert!(b.take::<usize>().is_err());
            });
            handles.push(h);
        }

        for h in handles {
            h.join().unwrap();
        }

        let c = a.take::<usize>();
        assert!(c.is_ok());
        assert_eq!(c.unwrap(), 10usize);
    }
}
