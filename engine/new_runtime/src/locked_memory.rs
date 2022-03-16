// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{memories::buffer::Buffer, MemoryError};
use core::fmt::Debug;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Memory that can be locked (unreadable) when storing sensitive data for longer period of time
// We implement everything on u8 currently because our current encryption code only returns u8. Future improvement may
// be to return type T: Bytes
pub trait LockedMemory: Debug + Zeroize + ZeroizeOnDrop + Sized + Clone {
    /// Modifies the value and potentially reallocates the data
    // Currently it only reallocates, can be improved for performance
    // Though reallocating is safer
    fn update(self, payload: Buffer<u8>, size: usize) -> Result<Self, MemoryError>;

    /// Unlocks the memory and returns a Buffer
    fn unlock(&self) -> Result<Buffer<u8>, MemoryError>;
}
