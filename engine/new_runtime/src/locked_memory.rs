use crate::types::Bytes;
use crate::memories::buffer::Buffer;
use crate::crypto_box::{BoxProvider, Key};
use core::fmt::Debug;


#[derive(Debug)]
pub enum MemoryError {
    EncryptionError,
    DecryptionError,
    ConfigurationNotAllowed,
}

pub enum ProtectedConfiguration {
    BufferConfig(usize),
    // FileConfig(usize),
}

// Different possible configuration for the memory
// This is still in development
#[derive(PartialEq, Eq)]
pub enum LockedConfiguration<P: BoxProvider> {
    // Default configuration when zeroed out
    ZeroedConfig(),
    // Encrypted ram memory, needs a key and size of non encrypted data
    EncryptedRamConfig(Key<P>, usize),
    // Encrypted file memory, needs a key and size of non encrypted data
    EncryptedFileConfig(Key<P>, usize),
    // Non contiguous memory in ram and disk
    NonContiguousInRamAndFileConfig(usize)
}

/// Memory buffers to store with default protections to store sensitive data
pub trait ProtectedMemory<T: Bytes>:
Debug + Sized {
    /// Writes the payload into a LockedMemory then locks it
    fn alloc(payload: &[T], config: ProtectedConfiguration)
             -> Result<Self, MemoryError>;

    /// Cleans up any trace of the memory used
    /// Shall be called in drop()
    fn dealloc(&mut self) -> Result<(), MemoryError>;
}


/// Memory that can be locked (unreadable) when storing sensitive data for longer period of time
pub trait LockedMemory<T: Bytes, P: BoxProvider>: Debug + Sized {
    /// Writes the payload into a LockedMemory then locks it
    fn alloc(payload: &[T], config: LockedConfiguration<P>)
             -> Result<Self, MemoryError>;

    /// Cleans up any trace of the memory used
    /// Shall be called in drop()
    fn dealloc(&mut self) -> Result<(), MemoryError>;

    /// Locks the memory and possibly reallocates
    fn lock(self, payload: Buffer<T>,  config: LockedConfiguration<P>)
        -> Result<Self, MemoryError>;

    /// Unlocks the memory and returns an unlocked Buffer
    fn unlock(&self, config: LockedConfiguration<P>)
        -> Result<Buffer<T>, MemoryError>;
}
