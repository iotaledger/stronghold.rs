use crate::types::Bytes;
use crate::memories::buffer::Buffer;
use crate::crypto_utils::crypto_box::{BoxProvider, Key};
use zeroize::{Zeroize};
use core::fmt::Debug;


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
    FileConfig(usize)
}

// Different possible configuration for the memory
// This is still in development
#[derive(PartialEq, Eq)]
pub enum LockedConfiguration<P: BoxProvider> {
    // Default configuration when zeroed out
    ZeroedConfig(),
    // Encrypted ram memory
    // Needs a key for encryption/decryption
    // Needs size for allocation but not for unlocking
    EncryptedRamConfig(Key<P>, Option<usize>),
    // Encrypted file memory, needs a key and size of non encrypted data
    EncryptedFileConfig(Key<P>, usize),
    // Non contiguous memory in ram and disk
    NonContiguousInRamAndFileConfig(usize)
}

/// Memory storage with default protections to store sensitive data
pub trait ProtectedMemory<T: Bytes>
    : Debug + Sized + Zeroize {

    /// Writes the payload into a LockedMemory then locks it
    fn alloc(payload: &[T], config: ProtectedConfiguration)
             -> Result<Self, MemoryError>;

    /// Cleans up any trace of the memory used
    /// Does not free any memory, the name may be misleading
    fn dealloc(&mut self) -> Result<(), MemoryError> {
        self.zeroize();
        Ok(())
    }
}


/// Memory that can be locked (unreadable) when storing sensitive data for longer period of time
pub trait LockedMemory<T: Bytes, P: BoxProvider>
    : Debug + Sized + Zeroize {

    /// Writes the payload into a LockedMemory then locks it
    fn alloc(payload: &[T], config: LockedConfiguration<P>)
             -> Result<Self, MemoryError>;

    /// Cleans up any trace of the memory used
    /// Shall be called in drop()
    fn dealloc(&mut self) -> Result<(), MemoryError> {
        self.zeroize();
        Ok(())
    }

    /// Locks the memory and possibly reallocates
    fn lock(self, payload: Buffer<T>,  config: LockedConfiguration<P>)
        -> Result<Self, MemoryError>;

    /// Unlocks the memory and returns an unlocked Buffer
    fn unlock(&self, config: LockedConfiguration<P>)
        -> Result<Buffer<T>, MemoryError>;
}
