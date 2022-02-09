
use crate::locked_memory::{*, LockedConfiguration::*, MemoryError::*, ProtectedConfiguration::*};
use crate::memories::buffer::Buffer;
use core::fmt::{self, Debug, Formatter};
use core::marker::PhantomData;
use crate::crypto_utils::crypto_box::{BoxProvider, Key};

use serde::{
    de::{Deserialize, Deserializer, SeqAccess, Visitor},
    ser::{Serialize, Serializer},
};


/// GuardedMemory is used when we want to store sensitive non encrypted data
/// This shall always be short lived
pub struct EncryptedRam<P: BoxProvider, const AD_SIZE: usize> {
    // Visibility within crate is for testing purpose
    // We currently only implement for u8 because our encryption functions only returns Vec[u8], therefore our cypher is Buffer<u8>
    cypher : Buffer<u8>,
    // Configuration, we should only allow EncryptedRamConfig for this struct
    // We do not store the key in the struct config, just random data for security
    config: LockedConfiguration<P>,
    // Associated data, we will use it as a nonce with random value
    ad : [u8; AD_SIZE],
}


// We currently only implement for u8 because our encryption functions only returns Vec[u8], therefore our cypher is Buffer<u8>
impl<P: BoxProvider, const AD_SIZE: usize> LockedMemory<u8, P> for
    EncryptedRam<P, AD_SIZE> {

    fn alloc(payload: &[u8], config: LockedConfiguration<P>)
             -> Result<Self, MemoryError> {
        match config {
            // For encrypted memory we don't store the key itself.
            EncryptedRamConfig(key, size) => {
                if size.is_none() { return Err(SizeNeededForAllocation) ;}
                let mut ad: [u8; AD_SIZE] = [0u8; AD_SIZE];
                P::random_buf(&mut ad).or(Err(EncryptionError))?;
                Ok(EncryptedRam {
                    // Encrypt the payload before storing it
                    cypher: {
                        let encrypted_payload =
                            P::box_seal(&key,
                                        &ad,
                                        payload)
                            .or(Err(EncryptionError))?;
                        Buffer::alloc(
                            &encrypted_payload,
                            BufferConfig(encrypted_payload.len()))
                            .expect("Failed to generate buffer")
                    },
                    // Don't put the actual key value, put random values, we don't want to store the key
                    // for security reasons
                    config: EncryptedRamConfig(Key::random(), size),
                    ad: ad
                })
            },

            // We don't allow any other configurations for EncryptedRam
            _ => Err(ConfigurationNotAllowed)
        }
    }

    fn dealloc(&mut self) -> Result<(), MemoryError> {
        self.cypher.dealloc()?;
        self.config = ZeroedConfig();
        Ok(())
    }

    /// Locks the memory and possibly reallocates
    // Currently we reallocate a new EncryptedRam at each lock
    // This improves security but decreases performance
    fn lock(self, payload: Buffer<u8>, config: LockedConfiguration<P>)
            -> Result<Self, MemoryError> {
        match config {
            EncryptedRamConfig(_, _) => EncryptedRam::<P, AD_SIZE>::alloc(&payload.borrow(), config),
            _ => Err(ConfigurationNotAllowed)
        }
    }

    /// Unlocks the memory
    fn unlock(&self, config: LockedConfiguration<P>)
              -> Result<Buffer<u8>, MemoryError> {
        // assert_matches!(self.config, EncryptedRamConfig(_,_));

        // Decrypt and store the value in a Buffer
        if let EncryptedRamConfig(key, None) = config {
            // Note: data is not in the protected buffer here, change box_open to return a Buffer type?
            let data = P::box_open(&key, &self.ad, &*self.cypher.borrow()).or(Err(DecryptionError))?;
            if let EncryptedRamConfig(_, Some(size)) = self.config {
                Buffer::alloc(&data, BufferConfig(size))
            } else {
                panic!("This should not happen if EncryptedRam has been allocated properly")
            }
        } else {
            return Err(ConfigurationNotAllowed);
        }
    }
}

impl<P: BoxProvider, const AD_SIZE: usize> Debug for EncryptedRam<P, AD_SIZE> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.cypher.fmt(f)
    }
}

unsafe impl<P: BoxProvider, const AD_SIZE: usize> Send for EncryptedRam<P, AD_SIZE> {}
unsafe impl<P: BoxProvider, const AD_SIZE: usize> Sync for EncryptedRam<P, AD_SIZE> {}

impl<P: BoxProvider, const AD_SIZE: usize> Serialize for EncryptedRam<P, AD_SIZE>
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

struct EncryptedRamVisitor<P: BoxProvider, const AD_SIZE: usize> {
    marker: PhantomData<fn() -> EncryptedRam<P, AD_SIZE>>,
}

impl<P: BoxProvider, const AD_SIZE: usize> EncryptedRamVisitor<P, AD_SIZE> {
    fn new() -> Self {
        EncryptedRamVisitor { marker: PhantomData }
    }
}

impl<'de, P: BoxProvider, const AD_SIZE: usize> Visitor<'de> for EncryptedRamVisitor<P, AD_SIZE>
{
    type Value = EncryptedRam<P, AD_SIZE>;

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

        // let seq = EncryptedRam::new(seq.len(), |s| s.copy_from_slice(seq.as_slice()));

        // Ok(seq)
    }
}

impl<'de, P: BoxProvider, const AD_SIZE: usize> Deserialize<'de> for EncryptedRam<P, AD_SIZE>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(EncryptedRamVisitor::new())
    }
}

mod tests {
    extern crate alloc;
    use super::*;
    use crate::crypto_utils::provider::Provider;
    use crate::locked_memory::*;

    use alloc::format;

    #[test]
    fn test_lock_unlock() {
        let key = Key::random();
        let ram = EncryptedRam::<Provider, 16>::alloc(&[1, 2, 3, 4, 5, 6][..], EncryptedRamConfig(key.clone(), Some(6)));
        assert!(ram.is_ok());
        let ram = ram.unwrap();
        let buf = ram.unlock(EncryptedRamConfig(key.clone(), None)); 
        assert!(buf.is_ok());
        let buf = buf.unwrap();
        assert_eq!((*buf.borrow()), [1, 2, 3, 4, 5, 6]);
        let ram = ram.lock(buf, EncryptedRamConfig(key.clone(), Some(6)));
        assert!(ram.is_ok());
    }

    #[test]
    fn test_crypto() {
        let key = Key::random();
        let ram = EncryptedRam::<Provider, 16>::alloc(&[1, 2, 3, 4, 5, 6][..], EncryptedRamConfig(key.clone(), Some(6)));
        assert!(ram.is_ok());
        let ram = ram.unwrap();
        let cypher = ram.cypher;
        assert_ne!(*cypher.borrow(), [1, 2, 3, 4, 5, 6]);
    }


    #[test]
    fn test_moving_and_cloning() {}
}

