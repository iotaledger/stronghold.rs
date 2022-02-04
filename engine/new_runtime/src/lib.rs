// No std maybe for later
#![no_std]

mod locked_memory;
mod buffer;
mod ram_memory;
mod file_memory;
mod noncontiguous_memory;
mod boxed;
mod types;

pub use types::Bytes;
