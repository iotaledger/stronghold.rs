// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    crypto_utils::crypto_box::{BoxProvider, Key},
    memories::buffer::Buffer,
    *,
};
use core::fmt::{self, Debug, Formatter};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum NCMemory {
    NCFile,
    NCRam,
    NCRamFile,
}

/// How the data is protected in memory.
/// - `Plain`: data is stored in clear with only basic protection from Ram or File
/// - `Encrypted`:  data is encrypted
/// - `NonContiguous`: data is split into different locations, all the shards are required to reconstruct the data
#[derive(Clone)]
pub enum Lock<P: BoxProvider> {
    Plain,
    Encryption(Key<P>),
    NonContiguous(NCMemory),
}

impl<P: BoxProvider> Debug for Lock<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{{ hidden }}")
    }
}

// We removes the key value when zeroing out the memory
impl<P: BoxProvider> Zeroize for Lock<P> {
    fn zeroize(&mut self) {
        if let Lock::Encryption(ref mut key) = self {
            key.zeroize()
        }
    }
}

/// Memory that can be locked (unreadable) when storing sensitive data for longer period of time
// We implement everything on u8 currently because our current encryption code only returns u8. Future improvement may
// be to return type T: Bytes
pub trait LockedMemory<P: BoxProvider>: Debug + Zeroize + ZeroizeOnDrop + Sized + Clone {
    /// Writes the payload into a LockedMemory then locks it
    fn alloc(payload: &[u8], size: usize, lock: Lock<P>) -> Result<Self, MemoryError>;

    /// Modifies the value and potentially reallocates the data
    // Currently it only reallocates, can be improved for performance
    // Though reallocating is safer
    fn update(self, payload: Buffer<u8>, size: usize, lock: Lock<P>) -> Result<Self, MemoryError>;

    /// Unlocks the memory and returns a Buffer
    fn unlock(&self, lock: Lock<P>) -> Result<Buffer<u8>, MemoryError>;
}
