// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    crypto_utils::crypto_box::{BoxProvider, Key},
    locked_memory::{Lock::*, *},
    memories::buffer::Buffer,
    MemoryError::{self, *},
};
use core::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use serde::{
    de::{Deserialize, Deserializer, SeqAccess, Visitor},
    ser::{Serialize, Serializer},
};

const AD_SIZE: usize = 32;

/// Protected ram memory that may be encrypted or not
/// If data is not encrypted this is basically a wrapper for the Buffer type
#[derive(Clone)]
pub struct RamMemory<P: BoxProvider> {
    buf: Buffer<u8>,
    // The kind of lock the data is under
    lock: Lock<P>,
    // Associated data, we will use it as a nonce with random value
    ad: [u8; AD_SIZE],
    // Size of the data when decrypted
    size: usize,
}

impl<P: BoxProvider> LockedMemory<P> for RamMemory<P> {
    fn alloc(payload: &[u8], size: usize, lock: Lock<P>) -> Result<Self, MemoryError> {
        if size == 0 {
            return Err(ZeroSizedNotAllowed);
        }
        let mut ad: [u8; AD_SIZE] = [0u8; AD_SIZE];
        P::random_buf(&mut ad).or(Err(EncryptionError))?;

        let encrypted: Vec<u8>;
        let (locked_data, locked_size, lock) = match lock {
            Plain => (payload, size, lock),

            // Encryption of data
            // We return a lock with random data rather than the actual key
            Encryption(ref key) => {
                encrypted = P::box_seal(key, &ad, payload).or(Err(EncryptionError))?;
                let size = encrypted.len();
                let lock = Encryption(Key::random());
                (encrypted.as_slice(), size, lock)
            }

            _ => return Err(LockNotAvailable),
        };

        Ok(RamMemory {
            buf: Buffer::alloc(locked_data, locked_size),
            lock,
            ad,
            size,
        })
    }

    /// Locks the memory and possibly reallocates
    // Currently we reallocate a new RamMemory at each lock
    // This improves security but decreases performance
    fn update(self, payload: Buffer<u8>, size: usize, lock: Lock<P>) -> Result<Self, MemoryError> {
        match lock {
            NonContiguous(_) => Err(LockNotAvailable),
            _ => RamMemory::<P>::alloc(&payload.borrow(), size, lock),
        }
    }

    /// Unlocks the memory
    fn unlock(&self, lock: Lock<P>) -> Result<Buffer<u8>, MemoryError> {
        if self.size == 0 {
            return Err(ZeroSizedNotAllowed);
        }
        if std::mem::discriminant(&lock) != std::mem::discriminant(&self.lock) {
            return Err(LockNotAvailable);
        }

        let buf_borrow = &*self.buf.borrow();
        let decrypted: Vec<u8>;
        let data = match lock {
            Plain => buf_borrow,
            Encryption(ref key) => {
                decrypted = P::box_open(key, &self.ad, buf_borrow).or(Err(DecryptionError))?;
                decrypted.as_slice()
            }
            _ => unreachable!("This should not happened if RamMemory has been allocated properly"),
        };

        Ok(Buffer::alloc(data, self.size))
    }
}

impl<P: BoxProvider> Zeroize for RamMemory<P> {
    fn zeroize(&mut self) {
        self.buf.zeroize();
        self.lock.zeroize();
        self.ad.zeroize();
        self.size.zeroize();
    }
}

impl<P: BoxProvider> ZeroizeOnDrop for RamMemory<P> {}

impl<P: BoxProvider> Drop for RamMemory<P> {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl<P: BoxProvider> Debug for RamMemory<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.buf.fmt(f)
    }
}

unsafe impl<P: BoxProvider> Send for RamMemory<P> {}
unsafe impl<P: BoxProvider> Sync for RamMemory<P> {}

impl<P: BoxProvider> Serialize for RamMemory<P> {
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

struct RamMemoryVisitor<P: BoxProvider> {
    marker: PhantomData<fn() -> RamMemory<P>>,
}

impl<P: BoxProvider> RamMemoryVisitor<P> {
    fn new() -> Self {
        RamMemoryVisitor { marker: PhantomData }
    }
}

impl<'de, P: BoxProvider> Visitor<'de> for RamMemoryVisitor<P> {
    type Value = RamMemory<P>;

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

impl<'de, P: BoxProvider> Deserialize<'de> for RamMemory<P> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(RamMemoryVisitor::new())
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use crate::crypto_utils::provider::Provider;

    #[test]
    fn ram_zeroize() {
        let key = Key::random();
        let ram = RamMemory::<Provider>::alloc(&[1, 2, 3, 4, 5, 6][..], 6, Encryption(key.clone()));
        assert!(ram.is_ok());
        let mut ram = ram.unwrap();
        ram.zeroize();

        // Check that the fields are zeroed
        assert_eq!(ram.ad, [0u8; AD_SIZE]);
        assert_eq!(ram.size, 0);
        if let Encryption(zeroed_key) = &ram.lock {
            assert_eq!(zeroed_key.bytes().len(), 0);
        }
        assert!((*ram.buf.borrow()).is_empty());
        assert!(ram.unlock(Encryption(key)).is_err());
    }
}
