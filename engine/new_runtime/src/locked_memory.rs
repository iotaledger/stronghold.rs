// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
use crate::{
    crypto_utils::crypto_box::{BoxProvider, Key},
    memories::buffer::Buffer,
    types::Bytes,
};
use core::fmt::Debug;
use zeroize::Zeroize;

#[derive(Debug)]
pub enum MemoryError {
    EncryptionError,
    DecryptionError,
    SizeNeededForAllocation,
    NCSizeNotAllowed,
    ConfigurationNotAllowed,
    FileSystemError,
}

#[derive(Debug)]
pub enum ProtectedConfiguration {
    ZeroedConfig(),
    BufferConfig(usize),
}

// Different possible configuration for the memory
// This is still in development
// Size is an Option type because size is required for memory allocation but
// not necessary for unlocking the memory
#[derive(Debug)]
pub enum LockedConfiguration<P: BoxProvider> {
    // Default configuration when zeroed out
    ZeroedConfig,

    // Non-encrypted file memory
    FileConfig(Option<usize>),

    // Encrypted ram memory
    // Needs a key for encryption/decryption
    // Needs size for allocation but not for unlocking
    EncryptedRam(Key<P>, Option<usize>),

    // Encrypted file memory, needs a key and size of non encrypted data
    EncryptedFile(Key<P>, Option<usize>),

    // Non contiguous non encrypted memory in ram and disk
    NCRamAndFileConfig(Option<usize>),

    // Non contiguous non encrypted memory in ram
    NCRamConfig(Option<usize>),
}

impl<P: BoxProvider> LockedConfiguration<P> {
    // Check that variants type are the same
    pub fn is_eq_config_type(&self, other: &Self) -> bool {
        use LockedConfiguration::*;
        match (self, other) {
            (ZeroedConfig, ZeroedConfig) => true,
            (FileConfig(_), FileConfig(_)) => true,
            (EncryptedRam(_, _), EncryptedRam(_, _)) => true,
            (EncryptedFile(_, _), EncryptedFile(_, _)) => true,
            (NCRamAndFileConfig(_), NCRamAndFileConfig(_)) => true,
            (NCRamConfig(_), NCRamConfig(_)) => true,
            (_, _) => false,
        }
    }
}

impl<P: BoxProvider> Zeroize for LockedConfiguration<P> {
    fn zeroize(&mut self) {
        *self = LockedConfiguration::ZeroedConfig
    }
}

// We implement PartialEq for configuration which contains a key
// We don't want to include the key in the comparison because when the
// configuration is stored in LockedMemory, the key is actually replaced
// with random noise to avoid storing sensitive data there
impl<P: BoxProvider> PartialEq for LockedConfiguration<P> {
    fn eq(&self, other: &Self) -> bool {
        use LockedConfiguration::*;
        match (self, other) {
            (ZeroedConfig, ZeroedConfig) => true,
            (FileConfig(s1), FileConfig(s2)) => s1 == s2,
            (EncryptedRam(_, s1), EncryptedRam(_, s2)) => s1 == s2,
            (EncryptedFile(_, s1), EncryptedFile(_, s2)) => s1 == s2,
            (NCRamAndFileConfig(s1), NCRamAndFileConfig(s2)) => s1 == s2,
            (NCRamConfig(s1), NCRamConfig(s2)) => s1 == s2,
            (_, _) => false,
        }
    }
}

impl<P: BoxProvider> Eq for LockedConfiguration<P> {}

/// Memory storage with default protections to store sensitive data
pub trait ProtectedMemory<T: Bytes>: Debug + Sized + Zeroize {
    /// Writes the payload into a LockedMemory then locks it
    fn alloc(payload: &[T], config: ProtectedConfiguration) -> Result<Self, MemoryError>;

    /// Cleans up any trace of the memory used
    /// Does not free any memory, the name may be misleading
    fn dealloc(&mut self) -> Result<(), MemoryError> {
        self.zeroize();
        Ok(())
    }
}

/// Memory that can be locked (unreadable) when storing sensitive data for longer period of time
pub trait LockedMemory<T: Bytes, P: BoxProvider>: Debug + Sized + Zeroize {
    /// Writes the payload into a LockedMemory then locks it
    fn alloc(payload: &[T], config: LockedConfiguration<P>) -> Result<Self, MemoryError>;

    /// Cleans up any trace of the memory used
    /// Shall be called in drop()
    fn dealloc(&mut self) -> Result<(), MemoryError> {
        self.zeroize();
        Ok(())
    }

    /// Locks the memory and possibly reallocates
    fn lock(self, payload: Buffer<T>, config: LockedConfiguration<P>) -> Result<Self, MemoryError>;

    /// Unlocks the memory and returns an unlocked Buffer
    fn unlock(&self, config: LockedConfiguration<P>) -> Result<Buffer<T>, MemoryError>;
}
