// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// No std maybe for later
// #![no_std]

mod boxed;
// pub mod crypto_utils;
// pub mod locked_memory;
pub mod memories;
mod types;

pub use types::Bytes;

/// The memory types of this crate shall return this message when trying to debug them
pub const DEBUG_MSG: &str = "Content of Locked Memory is hidden";

/// The different types of Error that may be encountered while using this crate
#[derive(Debug)]
pub enum MemoryError {
    EncryptionError,
    DecryptionError,
    NCSizeNotAllowed,
    LockNotAvailable,
    FileSystemError,
    ZeroSizedNotAllowed,
}
