
use crate::boxed::Boxed;
use crate::locked_memory::{*, MemoryConfiguration::*, MemoryError::*};
use crate::memories::buffer::Buffer;
use crate::types::{Bytes};
use core::fmt::{self, Debug, Formatter};
use core::marker::PhantomData;

use serde::{
    de::{Deserialize, Deserializer, SeqAccess, Visitor},
    ser::{Serialize, SerializeSeq, Serializer},
};

/// GuardedMemory is used when we want to store sensitive non encrypted data
/// This shall always be short lived
pub struct RamMemory<T: Bytes> {
    boxed : Boxed<T>, // the boxed type of current GuardedVec
    config: MemoryConfiguration
}


impl<T: Bytes> ProtectedMemory<T> for RamMemory<T> {

    fn alloc(payload: &[T], config: MemoryConfiguration)
             -> Result<Self, MemoryError> {
        match config {
            // For encrypted memory, check presence of a key
            EncryptedRam(key) => {
                Ok(RamMemory {
                    // Encrypt the payload before storing it
                    boxed: todo!(),
                    // Don't put the actual key value, put random values, we don't want to store the key
                    config: EncryptedRam(todo!())
                })
            },

            // We don't allow any other configurations for RamMemory
            _ => Err(ConfigurationNotAllowed)
        }
    }

    fn dealloc(&mut self) -> Result<(), MemoryError> {
        todo!()
    }
}

impl<T: Bytes> LockedMemory<T> for RamMemory<T> {
    /// Locks the memory and possibly reallocates
    // Currently we reallocate a new RamMemory at each lock
    // This improves security but decreases performance
    fn lock(self, payload: Buffer<T>, config: MemoryConfiguration)
            -> Result<Self, MemoryError> {
        match config {
            EncryptedRam(ref key) => RamMemory::alloc(&payload.borrow(), config),
            _ => Err(ConfigurationNotAllowed)
        }
    }

    /// Unlocks the memory
    fn unlock(&self, config: MemoryConfiguration)
                        -> Result<Buffer<T>, MemoryError> {
        match &self.config {
            // Decrypt and store the value in a Buffer
            EncryptedRam(key) => {
                todo!()
            }
            _ => panic!("This case should not happen if RamMemory has been allocated correctly")

        }
    }
}

impl<T: Bytes> Debug for RamMemory<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.boxed.fmt(f)
    }
}


unsafe impl<T: Bytes + Send> Send for RamMemory<T> {}
unsafe impl<T: Bytes + Sync> Sync for RamMemory<T> {}

impl<T: Bytes> Serialize for RamMemory<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
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

struct RamMemoryVisitor<T: Bytes> {
    marker: PhantomData<fn() -> RamMemory<T>>,
}

impl<T: Bytes> RamMemoryVisitor<T> {
    fn new() -> Self {
        RamMemoryVisitor { marker: PhantomData }
    }
}

impl<'de, T: Bytes> Visitor<'de> for RamMemoryVisitor<T>
where
    T: Deserialize<'de>,
{
    type Value = RamMemory<T>;

    fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str("GuardedVec not found")
    }

    fn visit_seq<E>(self, mut access: E) -> Result<Self::Value, E::Error>
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

impl<'de, T: Bytes> Deserialize<'de> for RamMemory<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(RamMemoryVisitor::new())
    }
}

