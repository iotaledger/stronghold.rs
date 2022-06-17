// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! The version lock is a special type word sized spin lock, that
//! contains a single bit to indicate a lock, while using the rest
//! of the bits for versioning.

use crate::stm::error::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

/// `VersionLock` is a special type of spinlock
#[derive(Default, Clone)]
pub struct VersionLock {
    atomic: Arc<AtomicUsize>,
}

impl VersionLock {
    /// Creates a new [`VersionLock`] with the desired version
    pub fn new(version: usize) -> Self {
        Self {
            atomic: Arc::new(AtomicUsize::new(version)),
        }
    }

    /// Tries to acquire a lock and returns an `Ok(())` on success.
    pub fn try_lock(&self) -> Result<(), TxError> {
        if self.is_locked() {
            return Err(TxError::LockPresent);
        }

        // set  lock bit
        self.atomic.fetch_or(!mask(), Ordering::SeqCst);

        Ok(())
    }

    /// Unlocks the [`VersionLock`] by simply clearing the lock bit
    #[inline(always)]
    pub fn unlock(&self) {
        self.atomic.fetch_and(mask(), Ordering::SeqCst);
    }

    /// Returns `true`, if the version lock is present
    pub fn is_locked(&self) -> bool {
        let n = self.atomic.load(Ordering::SeqCst);

        let lock_state = mask() & n;

        // check, if locked
        self.atomic
            .compare_exchange(
                mask() & n, // mask the lockbit and compare. if this is set the operation fails
                n,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .map_err(|_| TxError::LockPresent)
            .is_err()
    }

    /// Release the lock and increment the version
    pub fn release(&self) {
        // clear lock bit
        self.unlock();

        // increment version
        self.atomic.fetch_add(1, Ordering::SeqCst);
    }

    /// Returns the stored version
    pub fn version(&self) -> usize {
        self.atomic.load(Ordering::SeqCst) & mask()
    }
}

/// An atomic `VersionClock` with a simpler interface. This type should be
/// used for keeping track of a global version counter
#[derive(Clone, Default)]
pub struct VersionClock {
    atomic: Arc<AtomicUsize>,
}

impl VersionClock {
    pub fn new(version: usize) -> Self {
        Self {
            atomic: Arc::new(AtomicUsize::new(version)),
        }
    }

    /// Atomically increments the version and returns the previous value
    pub fn increment(&self) -> Result<usize, TxError> {
        Ok(self.atomic.fetch_add(1, Ordering::SeqCst))
    }

    /// Returns the current version
    pub fn version(&self) -> usize {
        self.atomic.load(Ordering::SeqCst)
    }
}

/// Returns the word size in number of bits
const fn word_size_bits() -> usize {
    std::mem::size_of::<usize>() * 8
}

/// Returns the number of bits to shift left to clear the most significant bit
const fn shift_by() -> usize {
    word_size_bits() - 1
}

/// Returns a bitmask to filter the most significant bit
const fn mask() -> usize {
    !(1 << shift_by())
}

#[cfg(test)]
mod tests {

    use rand::Rng;
    use threadpool::ThreadPool;

    use super::VersionLock;
    use crate::stm::TxError;

    #[test]
    fn test_version_lock() -> Result<(), TxError> {
        let lock = VersionLock::default();

        let max_runs = 0xFFFFF;
        let runs: u32 = rand::thread_rng().gen_range(0..max_runs);

        for _ in 0..runs {
            lock.try_lock()?;
            assert!(lock.is_locked());
            lock.release();
        }

        assert_eq!(lock.version(), runs as usize);

        Ok(())
    }

    #[test]
    fn test_version_lock_threaded() -> Result<(), TxError> {
        let lock = VersionLock::default();
        let max_runs = 0xFFFFF;
        let runs: u32 = rand::thread_rng().gen_range(0..max_runs);

        let threadpool = ThreadPool::new(8);

        // thread pool
        for i in 0..runs {
            let inner = lock.clone();
            threadpool.execute(move || {
                // some spin loop to wait for free lock
                while inner.try_lock().is_err() {}
                inner.release();
            })
        }

        threadpool.join();

        assert_eq!(lock.version(), runs as usize);

        Ok(())
    }
}
