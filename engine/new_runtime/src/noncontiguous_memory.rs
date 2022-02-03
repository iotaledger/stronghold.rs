use crate::file_memory::FileMemory;
use crate::ram_memory::RamMemory;
use crate::boxed_memory::MemoryConfiguration;
use crate::types::Bytes;
use zeroize::Zeroize;
use arrayvec::ArrayVec;

// NONCONTIGUOUS MEMORY
/// Shards of memory which composes a non contiguous memory
enum MemoryShard<T: Zeroize + Bytes> {
    File(FileMemory),
    Ram(RamMemory<T>)
}

const MAX_SHARDS: usize = 8;

pub struct NonContiguousMemory<T: Zeroize + Bytes> {
    index: ArrayVec<MemoryShard<T>, MAX_SHARDS>,
    config: MemoryConfiguration
}
