use zeroize::Zeroize;
use crate::types::Bytes;
use crate::ram_memory::*;


pub enum MemoryError {}
// Different possible configuration for the memory 
// This is still in development
pub enum MemoryConfiguration {
  Buffer,                       // short-lived ram memory
  EncryptedRam,                 // Encrypted ram memory
  EncryptedFile,                // Encrypted file memory
  NonContiguousInRamAndFile     // Non contiguous memory in ram and disk
}


// ########## SECURE MEMORY
// Secure memory is a trait which job is to provide "Secure memory"
pub trait BoxedMemory:
    Zeroize +
    Sized
{
    /// Writes the payload into a BoxedMemory then locks it
    fn alloc<T>(payload: T, config: MemoryConfiguration, key: Option<&[u8]>)
        -> Result<Self, MemoryError>
        where T: Zeroize + Bytes;

    /// Locks the memory and possibly reallocates
    fn lock<T>(self, payload: RamMemory<T>,  key: Option<&[u8]>)
        -> Result<Self, MemoryError>
        where T: Zeroize + Bytes;

    /// Unlocks the memory
    fn unlock<T>(&self, key: Option<&[u8]>)
        -> Result<RamMemory<T>, MemoryError>
        where T: Zeroize + Bytes;

    /// Cleans up any trace of the memory used
    /// Shall be called in drop()
    fn dealloc(&mut self) -> Result<(), MemoryError> {
        self.zeroize();
        Ok(())
    }
}
