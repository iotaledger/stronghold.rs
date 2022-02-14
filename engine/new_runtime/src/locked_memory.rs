use crate::crypto_utils::crypto_box::{BoxProvider, Key};
use crate::memories::buffer::Buffer;
use crate::types::Bytes;
use core::fmt::Debug;
use zeroize::Zeroize;

#[derive(Debug)]
pub enum MemoryError {
    EncryptionError,
    DecryptionError,
    SizeNeededForAllocation,
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
    ZeroedConfig(),

    // Non-encrypted file memory
    FileConfig(Option<usize>),

    // Encrypted ram memory
    // Needs a key for encryption/decryption
    // Needs size for allocation but not for unlocking
    EncryptedRamConfig(Key<P>, Option<usize>),
    // Encrypted file memory, needs a key and size of non encrypted data
    EncryptedFileConfig(Key<P>, Option<usize>),
    // Non contiguous memory in ram and disk
    NonContiguousInRamAndFileConfig(Option<usize>),
}

impl<P: BoxProvider> LockedConfiguration<P> {
    // Check that variants type are the same 
    pub fn is_eq_config_type(&self, other: &Self) -> bool {
        use LockedConfiguration::*;
        match (self, other) {
            (ZeroedConfig(), ZeroedConfig()) => true,
            (FileConfig(_), FileConfig(_)) => true,
            (EncryptedRamConfig(_, _), EncryptedRamConfig(_, _)) => true,
            (EncryptedFileConfig(_, _), EncryptedFileConfig(_, _)) => true,
            (NonContiguousInRamAndFileConfig(_), NonContiguousInRamAndFileConfig(_)) => true,
            (_, _) => false
        }
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
            (ZeroedConfig(), ZeroedConfig()) => true,
            (FileConfig(s1), FileConfig(s2)) => s1 == s2,
            (EncryptedRamConfig(_, s1), EncryptedRamConfig(_, s2)) => s1 == s2,
            (EncryptedFileConfig(_, s1), EncryptedFileConfig(_, s2)) => s1 == s2,
            (NonContiguousInRamAndFileConfig(s1), NonContiguousInRamAndFileConfig(s2)) => s1 == s2,
            (_, _) => false
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
