
use crate::locked_memory::{*, LockedConfiguration::*, MemoryError::*, ProtectedConfiguration::*};
use crate::memories::buffer::Buffer;
use crate::types::{Bytes};
use core::fmt::{self, Debug, Formatter};
use core::marker::PhantomData;
use crate::crypto_box::{BoxProvider, Key};

use serde::{
    de::{Deserialize, Deserializer, SeqAccess, Visitor},
    ser::{Serialize, Serializer},
};

const AD_SIZE : usize = 16;

/// GuardedMemory is used when we want to store sensitive non encrypted data
/// This shall always be short lived
pub struct EncryptedRam<T: Bytes, P: BoxProvider> {
    pub cypher : Buffer<T>,
    // Configuration, we should only allow EncryptedRamConfig for this struct
    // We do not store the key in the struct config, just random data for security
    config: LockedConfiguration<P>,
    // Associated data, we will use it as a nonce with random value
    ad : [u8; AD_SIZE],
}


// We currently implement for u8 because our encryption functions return Vec<u8>
impl<P: BoxProvider> LockedMemory<u8, P> for EncryptedRam<u8, P> {

    fn alloc(payload: &[u8], config: LockedConfiguration<P>)
             -> Result<Self, MemoryError> {
        match config {
            // For encrypted memory we don't store the key itself.
            EncryptedRamConfig(key, size) => {
                let mut ad: [u8; AD_SIZE] = [0u8; AD_SIZE];
                P::random_buf(&mut ad).or(Err(EncryptionError))?;
                Ok(EncryptedRam {
                    // Encrypt the payload before storing it
                    cypher: {
                        let encrypted_payload = P::box_seal(&key, &ad, payload).or(Err(EncryptionError))?;
                        Buffer::alloc(&encrypted_payload, BufferConfig(encrypted_payload.len()))
                            .expect("Failed to generate buffer")
                    },
                    // Don't put the actual key value, put random values, we don't want to store the key
                    // for security reasons
                    config: EncryptedRamConfig(Key::random(), size),
                    ad: ad
                })
            },

            // We don't allow any other configurations for RamMemory
            _ => Err(ConfigurationNotAllowed)
        }
    }

    fn dealloc(&mut self) -> Result<(), MemoryError> {
        self.cypher.dealloc()?;
        self.config = ZeroedConfig();
        Ok(())
    }

    /// Locks the memory and possibly reallocates
    // Currently we reallocate a new RamMemory at each lock
    // This improves security but decreases performance
    fn lock(self, payload: Buffer<u8>, config: LockedConfiguration<P>)
            -> Result<Self, MemoryError> {
        match config {
            EncryptedRamConfig(_, _) => EncryptedRam::alloc(&payload.borrow(), config),
            _ => Err(ConfigurationNotAllowed)
        }
    }

    /// Unlocks the memory
    fn unlock(&self, config: LockedConfiguration<P>)
              -> Result<Buffer<u8>, MemoryError> {
        // assert_matches!(self.config, EncryptedRamConfig(_,_));

        // Decrypt and store the value in a Buffer
        if let EncryptedRamConfig(key, size) = config {
            // Note: data is not in the protected buffer here, change box_open to return a Buffer type?
            let data = P::box_open(&key, &self.ad, &*self.cypher.borrow()).or(Err(DecryptionError))?;
            Buffer::alloc(&data, BufferConfig(size))
        } else {
            return Err(ConfigurationNotAllowed);
        }
    }
}

impl<T: Bytes, P: BoxProvider> Debug for EncryptedRam<T, P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.cypher.fmt(f)
    }
}

unsafe impl<T: Bytes + Send, P: BoxProvider> Send for EncryptedRam<T, P> {}
unsafe impl<T: Bytes + Sync, P: BoxProvider> Sync for EncryptedRam<T, P> {}

impl<T: Bytes, P: BoxProvider> Serialize for EncryptedRam<T, P>
where
    T: Serialize,
{
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

struct RamMemoryVisitor<T: Bytes, P: BoxProvider> {
    marker: PhantomData<fn() -> EncryptedRam<T, P>>,
}

impl<T: Bytes, P: BoxProvider> RamMemoryVisitor<T, P> {
    fn new() -> Self {
        RamMemoryVisitor { marker: PhantomData }
    }
}

impl<'de, T: Bytes, P: BoxProvider> Visitor<'de> for RamMemoryVisitor<T, P>
where
    T: Deserialize<'de>,
{
    type Value = EncryptedRam<T, P>;

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

impl<'de, T: Bytes, P: BoxProvider> Deserialize<'de> for EncryptedRam<T, P>
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

