// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! # Compatibility Module
//!  
//! This is a compatibility module, that must be replace with the upcoming memory
//! functionality for stronghold

use std::sync::{Arc, Mutex};
use thiserror::Error as DeriveError;
use zeroize::Zeroize;

pub enum MemoryConfiguration {}

pub struct GuardedMemory<T> {
    pub(crate) inner: T,
}

#[derive(DeriveError, Debug)]
pub enum MemoryError {
    #[error("Out of memory {0}")]
    OutOfMemory(String),
}

#[derive(DeriveError, Debug)]
pub enum KeyError {
    #[error("Could not derive key")]
    DerivationError,
}

/// The [`CompositeKey`] implements
/// a keying scheme, that fragments an initial key
/// and reconstructs the key on demand.
///
/// This impl is by no means the intended impl, but shall
/// provide minimal functionality
pub struct CompositeKey<K>
where
    K: AsRef<Vec<u8>> + Zeroize + Clone,
{
    x: Arc<Mutex<K>>,
    y: Arc<Mutex<K>>,
}

impl<K> CompositeKey<K>
where
    K: AsRef<Vec<u8>> + Zeroize + Clone,
{
    /// Initializes the internal key fragments, consume the
    /// provided actual key. The key must have a specific size,
    /// depending on the underlying hashing algorithm.
    pub fn new(key: K) -> Result<Self, KeyError> {
        Ok(Self {
            x: Arc::new(Mutex::new(key.clone())),
            y: Arc::new(Mutex::new(key)),
        })
    }

    /// `shuffle()` is being called either periodically, or event based.
    /// Internally it updates the key fragments, so no residual key fragment
    /// is retained in memory   
    async fn shuffle(&self) {}

    /// `key()` reconstructs the key and returns it as secure memory type
    /// The returned type must implement [`Zeroize`].
    pub fn key(&self) -> K {
        self.x.lock().expect("").clone()
    }
}

pub trait LockedMemory: Zeroize + Sized + Clone + PartialEq + std::fmt::Debug {
    /// Writes the payload into a GuardedMem then locks it
    fn alloc<T>(payload: T, config: MemoryConfiguration, key: Option<Vec<u8>>) -> Result<Self, MemoryError>
    where
        T: Zeroize + AsRef<Vec<u8>>;

    /// Locks the memory and possibly reallocates
    fn lock<T>(self, payload: GuardedMemory<T>, key: Option<Vec<u8>>) -> Result<Self, MemoryError>
    where
        T: Zeroize + AsRef<Vec<u8>>;

    /// Unlocks the memory
    fn unlock<T>(&self, key: Option<Vec<u8>>) -> Result<GuardedMemory<T>, MemoryError>
    where
        T: Zeroize + AsRef<Vec<u8>>;

    /// Cleans up any trace of the memory used
    /// Shall be called in drop()
    fn dealloc(&mut self) -> Result<(), MemoryError> {
        self.zeroize();
        Ok(())
    }
}

impl LockedMemory for usize {
    fn alloc<T>(payload: T, config: MemoryConfiguration, key: Option<Vec<u8>>) -> Result<Self, MemoryError>
    where
        T: Zeroize + AsRef<Vec<u8>>,
    {
        todo!()
    }

    fn lock<T>(self, payload: GuardedMemory<T>, key: Option<Vec<u8>>) -> Result<Self, MemoryError>
    where
        T: Zeroize + AsRef<Vec<u8>>,
    {
        todo!()
    }

    fn unlock<T>(&self, key: Option<Vec<u8>>) -> Result<GuardedMemory<T>, MemoryError>
    where
        T: Zeroize + AsRef<Vec<u8>>,
    {
        todo!()
    }
}
