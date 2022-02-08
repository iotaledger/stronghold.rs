use crate::types::Bytes;
use crate::memories::buffer::Buffer;
use core::fmt::Debug;


#[derive(Debug)]
pub enum MemoryError {
    ConfigurationNotAllowed,
    KeyNotProvided,
    PayloadNotAdequate,
    BufferNotLockable,
}
// Different possible configuration for the memory
// This is still in development
#[derive(PartialEq, Eq)]
pub enum MemoryConfiguration {
    // Clear ram memory which does not need any locking/unlocking
    // Shall be used as short-lived buffer
    ProtectedBuffer(usize),
    // Encrypted ram memory
    EncryptedRam(Buffer<u8>),
    // Encrypted file memory
    EncryptedFile(Buffer<u8>),
    // Non contiguous memory in ram and disk
    NonContiguousInRamAndFile(usize)
}

/// Memory buffers to store with default protections to store sensitive data
pub trait ProtectedMemory<T: Bytes>:
Debug + Sized {
    /// Writes the payload into a LockedMemory then locks it
    fn alloc(payload: &[T], config: MemoryConfiguration)
             -> Result<Self, MemoryError>;

    /// Cleans up any trace of the memory used
    /// Shall be called in drop()
    fn dealloc(&mut self) -> Result<(), MemoryError>;
}


/// Memory that can be locked (unreadable) when storing sensitive data for longer period of time
pub trait LockedMemory<T: Bytes>: ProtectedMemory<T> {
    /// Locks the memory and possibly reallocates
    fn lock(self, payload: Buffer<T>,  config: MemoryConfiguration)
        -> Result<Self, MemoryError>;

    /// Unlocks the memory and returns an unlocked Buffer
    fn unlock(&self, config: MemoryConfiguration)
        -> Result<Buffer<T>, MemoryError>;
}
