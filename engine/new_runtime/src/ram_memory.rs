
use crate::boxed::Boxed;
use crate::boxed_memory::MemoryConfiguration;
use crate::types::Bytes;
use zeroize::Zeroize;

/// GuardedMemory is used when we want to store sensitive non encrypted data
/// This shall always be short lived
pub struct RamMemory<T: Zeroize + Bytes> {
    data : Boxed<T>, // the boxed type of current GuardedVec
    config: MemoryConfiguration
}

