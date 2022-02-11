// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use zeroize::Zeroize;

use crate::{ctrl::MemoryController, LockedMemory, Transaction, TransactionError};
use log::*;
use std::{
    cmp::Ordering,
    hash::{Hash, Hasher},
    ops::Deref,
    sync::{Arc, Mutex},
};

/// Represents a transactional variable, that
/// can be read from and written to.
pub struct TVar<T>
where
    T: Send + Sync + LockedMemory,
{
    /// this controller takes care of access to the underlying value.
    pub(crate) value: Option<MemoryController<Transaction<T>, T>>,
}

impl<T> TVar<T>
where
    T: Send + Sync + LockedMemory,
{
    pub fn new(var: T) -> Self {
        Self {
            value: Some(MemoryController::new(var)),
        }
    }

    /// Reads the value of the inner value without a transaction
    /// FIXME: Do we really need this function,  or is this "only" required
    /// for tests
    pub fn read(&self) -> Result<Arc<T>, TransactionError> {
        if let Some(ctrl) = &self.value {
            return ctrl.read();
        }

        Err(TransactionError::InconsistentState)
    }

    /// Changes the inner var
    pub fn write(&self, value: T) -> Result<(), TransactionError> {
        if let Some(ctrl) = &self.value {
            return ctrl.write(value);
        }

        Err(TransactionError::InconsistentState)
    }
}

impl<T> Clone for TVar<T>
where
    T: Send + Sync + LockedMemory,
{
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
        }
    }
}

impl<T> PartialEq for TVar<T>
where
    T: Send + Sync + LockedMemory,
{
    fn eq(&self, other: &Self) -> bool {
        match self.read() {
            Ok(a) => match other.read() {
                Ok(b) => a == b,
                Err(_) => false,
            },
            Err(e) => false,
        }
    }
}

impl<T> PartialOrd for TVar<T>
where
    T: Send + Sync + LockedMemory,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let a = &self as *const _ as *const usize as usize;
        let b = &other as *const _ as *const usize as usize;

        match a {
            _ if a > b => Some(Ordering::Greater),
            _ if a < b => Some(Ordering::Less),
            _ => Some(Ordering::Equal),
        }
    }
}

impl<T> Hash for TVar<T>
where
    T: Send + Sync + LockedMemory,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_usize((&self as *const _ as *const usize) as usize);
        state.finish();
    }
}

impl<T> Ord for TVar<T>
where
    T: Send + Sync + LockedMemory,
{
    fn cmp(&self, other: &Self) -> Ordering {
        let a = &self as *const _ as *const usize as usize;
        let b = &other as *const _ as *const usize as usize;

        match a {
            _ if a > b => Ordering::Greater,
            _ if a < b => Ordering::Less,
            _ => Ordering::Equal,
        }
    }
}

impl<T> Eq for TVar<T> where T: Send + Sync + LockedMemory {}

/// Transactional Log type. The intend of this type
/// is to track each operation on the target value
#[derive(Zeroize, Debug, Clone)]
pub enum TLog<T>
where
    T: Send + Sync + LockedMemory,
{
    /// Indicates that a variable has been read
    Read(T),

    /// Indicates that a variable has been modified
    Write(T),

    /// Store (original, updated)
    ReadWrite(T, T),
}

impl<T> TLog<T>
where
    T: Send + Sync + LockedMemory,
{
    pub fn read(&mut self) -> Result<T, TransactionError> {
        match self {
            Self::Read(inner) => Ok(inner.clone()),
            Self::Write(ref inner) | Self::ReadWrite(_, ref inner) => Ok(inner.clone()),
        }
    }

    pub fn write(&mut self, update: T) -> Result<(), TransactionError> {
        info!("Update Tlog With Value: '{:?}'", update);
        *self = match self {
            Self::Write(ref inner) => {
                info!("Update Tlog::Write With Value: '{:?}'", inner);
                Self::Write(update)
            }
            Self::Read(ref inner) | Self::ReadWrite(_, ref inner) => {
                info!("Update Tlog::Read|ReadWrite With Value: '{:?}'", inner);
                Self::ReadWrite(inner.clone(), update)
            }
        };

        Ok(())
    }
}

impl<T> Deref for TLog<T>
where
    T: Send + Sync + LockedMemory,
{
    type Target = T;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Read(inner) => inner,
            Self::Write(inner) => inner,
            Self::ReadWrite(_, inner) => inner,
        }
    }
}

/// A trait to wrap easy access to a mutex guarded inner variable
pub(crate) trait MutexAccessor<T> {
    /// Returns a referncee to the inner mutex guarded
    /// variable
    fn get(&self) -> &Mutex<T>;
}

/// [`MutexLocker`] provides functionality to modify mutex guarded types
pub(crate) trait MutexLocker<T>: MutexAccessor<T> {
    /// Access to immutable inner data of the mutex inside a function closure
    /// Returns a result with the inner type
    #[inline(always)]
    fn apply<F, R>(&self, operation: F) -> Result<R, TransactionError>
    where
        F: Fn(&T) -> Result<R, TransactionError>,
    {
        operation(&*self.get().lock().map_err(TransactionError::to_inner)?)
    }

    /// Access to mutable inner data of the mutex inside a function closure.
    /// Returns a result with the inner type
    #[inline(always)]
    fn apply_mut<F, R>(&self, operation: F) -> Result<R, TransactionError>
    where
        F: Fn(&mut T) -> Result<R, TransactionError>,
    {
        operation(&mut *self.get().lock().map_err(TransactionError::to_inner)?)
    }
}

pub(crate) mod structures {

    #[derive(Default)]
    pub struct OrderedLog<K, V>
    where
        K: Eq + Clone,
        V: Clone,
    {
        ctrl: Option<K>,
        entries: Vec<V>,
    }

    impl<K, V> OrderedLog<K, V>
    where
        K: Eq + Clone,
        V: Clone,
    {
        pub fn new() -> Self {
            Self {
                ctrl: None,
                entries: Vec::new(),
            }
        }
    }

    impl<K, V> Iterator for OrderedLog<K, V>
    where
        K: Eq + Clone,
        V: Clone,
    {
        type Item = (K, V);

        fn next(&mut self) -> Option<Self::Item> {
            // if let Some(value) = self.entries.iter().next() {
            //     if let Some(ctrl) = self.ctrl {
            //         return Some((ctrl, value.clone()));
            //     }
            // }
            // None
            todo!()
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use rand::{distributions::Alphanumeric, Rng};
    use std::collections::HashMap;

    #[derive(Default)]
    struct Numbers {
        data: Arc<Mutex<HashMap<String, String>>>,
    }

    impl MutexAccessor<HashMap<String, String>> for Numbers {
        fn get(&self) -> &std::sync::Mutex<HashMap<String, String>> {
            &self.data
        }
    }

    impl MutexLocker<HashMap<String, String>> for Numbers {}

    #[test]
    fn test_mutex_access() {
        let num_runs = 100;
        let num_threads = 64;
        let numbers = Arc::new(Numbers::default());

        let rand_string = || {
            rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(rand::thread_rng().gen_range(1..127))
                .map(char::from)
                .collect::<String>()
        };

        for _ in 0..num_runs {
            let mut threads = Vec::new();

            // generate random strings
            let mut data = vec![("".to_string(), "".to_string()); num_threads];
            data.fill_with(|| (rand_string(), rand_string()));

            // create a copy to be drained
            let mut queue = data.clone();

            for _ in 0..num_threads {
                let n = numbers.clone();

                threads.push(match queue.pop() {
                    Some((k, v)) => std::thread::spawn(move || {
                        n.apply_mut(|inner| {
                            inner.insert(k.clone(), v.clone());

                            Ok(())
                        })
                    }),
                    None => break,
                });
            }

            for th in threads {
                assert!(th.join().is_ok());
            }

            for (k, v) in data {
                assert!(numbers.apply(|inner| Ok(inner.get(&k).unwrap().eq(&v))).unwrap())
            }
        }
    }
}
