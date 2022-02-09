use crate::memories::file_memory::FileMemory;
use crate::memories::buffer::Buffer;
// use crate::memories::encrypted_ram::EncryptedRam;
use crate::crypto_box::{BoxProvider};
use crate::locked_memory::LockedConfiguration;
use crate::types::Bytes;
use zeroize::Zeroize;

// NONCONTIGUOUS MEMORY
/// Shards of memory which composes a non contiguous memory
enum MemoryShard<T: Zeroize + Bytes> {
    File(FileMemory),
    Ram(Buffer<T>)
}

// We set the maximum number of shards to 8, this is an arbitrary value that can be discussed
const MAX_SHARDS: usize = 8;

pub struct NonContiguousMemory<T: Zeroize + Bytes, P: BoxProvider> {
    index: [MemoryShard<T>; MAX_SHARDS],
    config: LockedConfiguration<P>
}
