use crate::crypto_utils::crypto_box::{BoxProvider, Key};
use crate::memories::buffer::Buffer;
use core::fmt::Debug;
use zeroize::{Zeroize};

#[derive(Debug)]
pub enum MemoryError {
    EncryptionError,
    DecryptionError,
    NCSizeNotAllowed,
    ConfigurationNotAllowed,
    FileSystemError,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum NCMemory {
    NCFile,
    NCRam,
    NCRamFile,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MemoryType {
    Ram,
    File,
    NonContiguous(NCMemory),
}

#[derive(Debug, Clone)]
pub struct LockedConfiguration<P: BoxProvider> {
    pub mem_type: MemoryType,
    pub encrypted: Option<Key<P>>,
}

impl<P: BoxProvider> Zeroize for LockedConfiguration<P> {
    fn zeroize(&mut self) {
        if self.encrypted.is_some() {
            self.encrypted.zeroize()
        }
    }
}


// We implement PartialEq for configuration which contains a key
// We don't want to include the key in the comparison because when the
// configuration is stored in LockedMemory, the key is actually replaced
// with random noise to avoid storing sensitive data there
impl<P: BoxProvider> PartialEq for LockedConfiguration<P> {
    fn eq(&self, other: &Self) -> bool {
        self.mem_type == other.mem_type
            && std::mem::discriminant(&self.encrypted) == std::mem::discriminant(&other.encrypted)
    }
}

impl<P: BoxProvider> Eq for LockedConfiguration<P> {}

/// Memory that can be locked (unreadable) when storing sensitive data for longer period of time
pub trait LockedMemory<P: BoxProvider>: Debug + Zeroize + Drop + Sized {
    /// Writes the payload into a LockedMemory then locks it
    fn alloc(payload: &[u8], size: usize, config: LockedConfiguration<P>) -> Result<Self, MemoryError>;

    /// Modifies the value and potentially reallocates the data
    fn update(self, payload: Buffer<u8>, size: usize, config: LockedConfiguration<P>) -> Result<Self, MemoryError>;

    /// Unlocks the memory and returns an unlocked Buffer
    fn unlock(&self, config: LockedConfiguration<P>) -> Result<Buffer<u8>, MemoryError>;
}
