// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// No std maybe for later
// #![no_std]

mod boxed;
pub mod locked_memory;
pub mod memories;
mod types;
pub mod utils;

pub use thiserror::Error as DeriveError;
pub use types::Bytes;

/// The memory types of this crate shall return this message when trying to debug them
pub const DEBUG_MSG: &str = "Content of Locked Memory is hidden";

/// The different types of Error that may be encountered while using this crate
#[derive(Debug, DeriveError)]
pub enum MemoryError {
    #[error("encryption error")]
    EncryptionError,

    #[error("decryption error")]
    DecryptionError,

    #[error("illegal non-contiguous size")]
    NCSizeNotAllowed,

    #[error("error while refreshing non-contiguous memory")]
    NCRefreshError,

    #[error("lock unavailable")]
    LockNotAvailable,

    #[error("file system error")]
    FileSystemError,

    #[error("illegal zero-sized value provided")]
    ZeroSizedNotAllowed,

    #[error("failed to allocate memory ({0})")]
    Allocation(String),

    #[error("intended operation failed: ({0})")]
    Operation(String),

    #[error("illegal tentative of using zeroized memory")]
    IllegalZeroizedUsage,
}

/// A simple trait to force the types to call `zeroize()` when dropping
pub trait ZeroizeOnDrop {}
