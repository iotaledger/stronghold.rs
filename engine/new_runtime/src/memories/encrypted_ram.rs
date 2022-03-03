use crate::crypto_utils::crypto_box::{BoxProvider, Key};
use crate::locked_memory::{MemoryError::*, MemoryType::Ram, *};
use crate::memories::buffer::Buffer;
use core::fmt::{self, Debug, Formatter};
use core::marker::PhantomData;
use zeroize::{Zeroize};

use serde::{
    de::{Deserialize, Deserializer, SeqAccess, Visitor},
    ser::{Serialize, Serializer},
};

// Additional data used as nonce
const AD_SIZE: usize = 32;

/// Buffer type in which the data is encrypted
pub struct EncryptedRam<P: BoxProvider> {
    // Visibility within crate is for testing purpose
    // We currently only implement for u8 because our encryption functions only returns Vec[u8], therefore our cipher is Buffer<u8>
    cipher: Buffer<u8>,
    // Configuration, we should only allow EncryptedRamConfig for this struct
    // We do not store the key in the struct config, just random data for security
    config: LockedConfiguration<P>,
    // Associated data, we will use it as a nonce with random value
    ad: [u8; AD_SIZE],
    // Size of the data when decrypted
    size: usize
}

// We currently only implement for u8 because our encryption functions only returns Vec[u8], therefore our cipher is Buffer<u8>
impl<P: BoxProvider> LockedMemory<P> for EncryptedRam<P> {
    fn alloc(payload: &[u8], size: usize, config: LockedConfiguration<P>) -> Result<Self, MemoryError> {
        match config {
            // For encrypted memory we don't store the key itself.
            LockedConfiguration { mem_type: Ram, encrypted: Some(ref key) } => {
                let mut ad: [u8; AD_SIZE] = [0u8; AD_SIZE];
                P::random_buf(&mut ad).or(Err(EncryptionError))?;
                Ok(EncryptedRam {
                    // Encrypt the payload before storing it
                    cipher: {
                        let encrypted_payload = P::box_seal(key, &ad, payload).or(Err(EncryptionError))?;
                        Buffer::alloc(&encrypted_payload, encrypted_payload.len())
                    },
                    // Don't put the actual key value, put random values, we don't want to store the key
                    // for security reasons
                    config: LockedConfiguration { mem_type: Ram, encrypted: Some(Key::random()) },
                    ad,
                    size
                })
            }

            // We don't allow any other configurations for EncryptedRam
            _ => Err(ConfigurationNotAllowed),
        }
    }

    /// Locks the memory and possibly reallocates
    // Currently we reallocate a new EncryptedRam at each lock
    // This improves security but decreases performance
    fn update(self, payload: Buffer<u8>, size: usize, config: LockedConfiguration<P>) -> Result<Self, MemoryError> {
        match config {
            LockedConfiguration { mem_type: Ram, encrypted: Some(_) } => {
                EncryptedRam::<P>::alloc(&payload.borrow(), size, config)
            },
            _ => Err(ConfigurationNotAllowed),
        }
    }

    /// Unlocks the memory
    fn unlock(&self, config: LockedConfiguration<P>) -> Result<Buffer<u8>, MemoryError> {
        // Decrypt and store the value in a Buffer
        match config {
            LockedConfiguration { mem_type: Ram, encrypted: Some(ref key) } => {
                // Note: data is not in the protected buffer here, change box_open to return a Buffer type?
                let data = P::box_open(key, &self.ad, &*self.cipher.borrow()).or(Err(DecryptionError))?;
                Ok(Buffer::alloc(&data, self.size))
            },
            _ => Err(ConfigurationNotAllowed)
        }
    }
}



impl<P: BoxProvider> Zeroize for EncryptedRam<P> {
    fn zeroize(&mut self) {
        self.cipher.zeroize();
        self.config.zeroize(); 
        self.ad.zeroize();
        self.size.zeroize();
    }
}

impl<P: BoxProvider> Drop for EncryptedRam<P> {
    fn drop(&mut self) {
        self.zeroize()
    }
}


impl<P: BoxProvider> Debug for EncryptedRam<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.cipher.fmt(f)
    }
}

unsafe impl<P: BoxProvider> Send for EncryptedRam<P> {}
unsafe impl<P: BoxProvider> Sync for EncryptedRam<P> {}

impl<P: BoxProvider> Serialize for EncryptedRam<P> {
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

struct EncryptedRamVisitor<P: BoxProvider> {
    marker: PhantomData<fn() -> EncryptedRam<P>>,
}

impl<P: BoxProvider> EncryptedRamVisitor<P> {
    fn new() -> Self {
        EncryptedRamVisitor { marker: PhantomData }
    }
}

impl<'de, P: BoxProvider> Visitor<'de> for EncryptedRamVisitor<P> {
    type Value = EncryptedRam<P>;

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

impl<'de, P: BoxProvider> Deserialize<'de> for EncryptedRam<P> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(EncryptedRamVisitor::new())
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use crate::crypto_utils::provider::Provider;

    #[test]
    fn test_lock_unlock() {
        let key = Key::random();
        let ram =
            EncryptedRam::<Provider>::alloc(&[1, 2, 3, 4, 5, 6][..], 6, LockedConfiguration { mem_type: Ram, encrypted: (Some(key.clone())) });
        assert!(ram.is_ok());
        let ram = ram.unwrap();
        let buf = ram.unlock(LockedConfiguration { mem_type: Ram, encrypted: (Some(key.clone())) });
        assert!(buf.is_ok());
        let buf = buf.unwrap();
        assert_eq!((*buf.borrow()), [1, 2, 3, 4, 5, 6]);
        let ram = ram.update(buf, 6, LockedConfiguration { mem_type: Ram, encrypted: (Some(key.clone())) });
        assert!(ram.is_ok());
    }

    #[test]
    fn test_crypto() {
        let key = Key::random();
        let ram =
            EncryptedRam::<Provider>::alloc(&[1, 2, 3, 4, 5, 6][..], 6, LockedConfiguration { mem_type: Ram, encrypted: (Some(key.clone())) });
        assert!(ram.is_ok());
        let ram = ram.unwrap();
        let cipher = &ram.cipher;
        assert_ne!(*cipher.borrow(), [1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn test_zeroize() {
        let key = Key::random();
        let ram =
            EncryptedRam::<Provider>::alloc(&[1, 2, 3, 4, 5, 6][..], 6, LockedConfiguration { mem_type: Ram, encrypted: (Some(key.clone())) });
        assert!(ram.is_ok());
        let mut ram = ram.unwrap();
        ram.zeroize();
    }
}
