// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! # Compatibility Module
//!  
//! This is a compatibility module, that must be replace with the upcoming memory
//! functionality for stronghold

use thiserror::Error as DeriveError;
use zeroize::Zeroize;

pub enum MemoryConfiguration {}

pub struct GuardedMemory<T> {
    inner: T,
}

#[derive(DeriveError, Debug)]
pub enum MemoryError {
    #[error("Out of memory {0}")]
    OutOfMemory(String),
}

pub trait BoxedMemory: Zeroize + Sized + Clone {
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

impl BoxedMemory for usize {
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
