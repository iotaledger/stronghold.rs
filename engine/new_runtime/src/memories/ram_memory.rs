// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    locked_memory::LockedMemory,
    memories::buffer::Buffer,
    MemoryError::{self, *},
    ZeroizeOnDrop, DEBUG_MSG,
};
use core::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
};
use zeroize::Zeroize;

use serde::{
    de::{Deserialize, Deserializer, SeqAccess, Visitor},
    ser::{Serialize, Serializer},
};

/// Protected ram memory that may be encrypted or not
/// This is basically a wrapper for the Buffer type, but the usage
/// is different, buffer type are meant for short lived usage while
/// RamMemory can store data for longer period of time.
/// Hence data in RamMemory has to be either encyrpted or protected
/// behind a scheme
#[derive(Clone)]
pub struct RamMemory {
    buf: Buffer<u8>,
    // Size of the data when decrypted
    size: usize,
}

impl RamMemory {
    pub fn alloc(payload: &[u8], size: usize) -> Result<Self, MemoryError> {
        if size == 0 {
            return Err(ZeroSizedNotAllowed);
        }

        Ok(RamMemory {
            buf: Buffer::alloc(payload, size),
            size,
        })
    }
}

impl LockedMemory for RamMemory {
    /// Locks the memory and possibly reallocates
    // Currently we reallocate a new RamMemory at each lock
    // This improves security but decreases performance
    fn update(self, payload: Buffer<u8>, size: usize) -> Result<Self, MemoryError> {
        RamMemory::alloc(&payload.borrow(), size)
    }

    /// Unlocks the memory
    fn unlock(&self) -> Result<Buffer<u8>, MemoryError> {
        if self.size == 0 {
            return Err(ZeroSizedNotAllowed);
        }

        let buf_borrow = &*self.buf.borrow();
        Ok(Buffer::alloc(buf_borrow, self.size))
    }
}

impl Zeroize for RamMemory {
    fn zeroize(&mut self) {
        self.buf.zeroize();
        self.size.zeroize();
    }
}

impl ZeroizeOnDrop for RamMemory {}

impl Drop for RamMemory {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl Debug for RamMemory {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", DEBUG_MSG)
    }
}

unsafe impl Send for RamMemory {}
unsafe impl Sync for RamMemory {}

impl Serialize for RamMemory {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        todo!();
        // let mut state = serializer.serialize_seq(Some(self.len()))?;
        // for e in self.borrow().iter() {
        //     state.serialize_element(e)?;
        // }
        // state.end()
    }
}

struct RamMemoryVisitor {
    marker: PhantomData<fn() -> RamMemory>,
}

impl RamMemoryVisitor {
    fn new() -> Self {
        RamMemoryVisitor { marker: PhantomData }
    }
}

impl<'de> Visitor<'de> for RamMemoryVisitor {
    type Value = RamMemory;

    fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str("GuardedVec not found")
    }

    fn visit_seq<E>(self, mut _access: E) -> Result<Self::Value, E::Error>
    where
        E: SeqAccess<'de>,
    {
        todo!()
        // extern crate alloc;
        // use alloc::vec::Vec;

        // let mut seq = Vec::<T>::with_capacity(access.size_hint().unwrap_or(0));

        // while let Some(e) = access.next_element()? {
        //     seq.push(e);
        // }

        // let seq = RamMemory::new(seq.len(), |s| s.copy_from_slice(seq.as_slice()));

        // Ok(seq)
    }
}

impl<'de> Deserialize<'de> for RamMemory {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(RamMemoryVisitor::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ram_zeroize() {
        let ram = RamMemory::alloc(&[1, 2, 3, 4, 5, 6][..], 6);
        assert!(ram.is_ok());
        let mut ram = ram.unwrap();
        ram.zeroize();

        // Check that the fields are zeroed
        assert_eq!(ram.size, 0);
        assert!((*ram.buf.borrow()).is_empty());
        assert!(ram.unlock().is_err());
    }
}
