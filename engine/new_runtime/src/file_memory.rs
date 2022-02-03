use crate::boxed_memory::MemoryConfiguration;

const FILENAME_SIZE: usize = 16;

/// File memory
pub struct FileMemory {
    // Filename are random string of 16 characters
    fname: [u8; FILENAME_SIZE],
    config: MemoryConfiguration
}
