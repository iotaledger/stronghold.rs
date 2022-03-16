// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    crypto_utils::{crypto_box::BoxProvider, utils::*},
    locked_memory::{
        Lock::{self, *},
        LockedMemory,
        NCMemory::{NCRam, NCRamFile},
    },
    memories::{buffer::Buffer, file_memory::FileMemory, ram_memory::RamMemory},
    MemoryError::{self, *},
    DEBUG_MSG,
};
use core::fmt::{self, Debug, Formatter};
use crypto::hashes::sha;
use zeroize::{Zeroize, ZeroizeOnDrop};

static IMPOSSIBLE_CASE: &str = "NonContiguousMemory: this case should not happen if allocated properly";

// Currently we only support data of 32 bytes in noncontiguous memory
pub const NC_DATA_SIZE: usize = 32;

// NONCONTIGUOUS MEMORY
/// Shards of memory which composes a non contiguous memory
#[derive(Clone)]
enum MemoryShard<P: BoxProvider> {
    FileShard(FileMemory<P>),
    RamShard(RamMemory<P>),
}
use MemoryShard::*;

/// NonContiguousMemory only works on data which size corresponds to the hash primitive we use. In our case we use it to
/// store keys hence the size of the data depends on the chosen box provider
#[derive(Clone)]
pub struct NonContiguousMemory<P: BoxProvider> {
    shard1: MemoryShard<P>,
    shard2: MemoryShard<P>,
    lock: Lock<P>,
}

impl<P: BoxProvider> LockedMemory<P> for NonContiguousMemory<P> {
    /// Writes the payload into a LockedMemory then locks it
    fn alloc(payload: &[u8], size: usize, lock: Lock<P>) -> Result<Self, MemoryError> {
        if size != NC_DATA_SIZE {
            return Err(NCSizeNotAllowed);
        };
        let random = P::random_vec(NC_DATA_SIZE).expect("Failed to generate random vec");
        let mut digest = [0u8; NC_DATA_SIZE];
        sha::SHA256(&random, &mut digest);
        let digest = xor(&digest, payload, NC_DATA_SIZE);

        let ram1 = RamMemory::alloc(&random, NC_DATA_SIZE, Plain)?;
        let shard1 = RamShard(ram1);
        let shard2 = match lock {
            NonContiguous(NCRamFile) => {
                let fmem = FileMemory::alloc(&digest, NC_DATA_SIZE, Plain)?;
                FileShard(fmem)
            }
            NonContiguous(NCRam) => {
                let ram2 = RamMemory::alloc(&digest, NC_DATA_SIZE, Plain)?;
                RamShard(ram2)
            }
            // We don't allow any other configurations
            _ => {
                return Err(LockNotAvailable);
            }
        };

        Ok(NonContiguousMemory { shard1, shard2, lock })
    }

    /// Locks the memory and possibly reallocates
    fn update(self, payload: Buffer<u8>, size: usize, lock: Lock<P>) -> Result<Self, MemoryError> {
        NonContiguousMemory::alloc(&payload.borrow(), size, lock)
    }

    /// Unlocks the memory and returns an unlocked Buffer
    // To retrieve secret value you xor the hash contained in shard1 with value in shard2
    fn unlock(&self, _lock: Lock<P>) -> Result<Buffer<u8>, MemoryError> {
        let mut data1 = [0u8; NC_DATA_SIZE];
        sha::SHA256(&self.get_buffer_from_shard1().borrow(), &mut data1);
        let data = match &self.shard2 {
            RamShard(ram2) => {
                let buf = ram2.unlock(Plain)?;
                let x = xor(&data1, &buf.borrow(), NC_DATA_SIZE);
                x
            }
            FileShard(fm) => {
                let buf = fm.unlock(Plain)?;
                let x = xor(&data1, &buf.borrow(), NC_DATA_SIZE);
                x
            }
        };
        Ok(Buffer::alloc(&data, NC_DATA_SIZE))
    }
}

impl<P: BoxProvider> NonContiguousMemory<P> {
    fn get_buffer_from_shard1(&self) -> Buffer<u8> {
        match &self.shard1 {
            RamShard(ram) => ram.unlock(Plain).expect("Failed to retrieve buffer from Ram shard"),
            _ => unreachable!("{}", IMPOSSIBLE_CASE),
        }
    }

    // Refresh the shards to increase security, may be called every _n_ seconds or
    // punctually
    #[allow(dead_code)]
    fn refresh(self) -> Result<Self, MemoryError> {
        let random = P::random_vec(NC_DATA_SIZE).expect("Failed to generate random vec");

        // Refresh shard1
        let buf_of_old_shard1 = self.get_buffer_from_shard1();
        let data_of_old_shard1 = &buf_of_old_shard1.borrow();
        let new_data1 = xor(data_of_old_shard1, &random, NC_DATA_SIZE);
        let new_shard1 = RamShard(RamMemory::alloc(&new_data1, NC_DATA_SIZE, Plain)?);
        let mut hash_of_old_shard1 = [0u8; NC_DATA_SIZE];
        let mut hash_of_new_shard1 = [0u8; NC_DATA_SIZE];
        sha::SHA256(data_of_old_shard1, &mut hash_of_old_shard1);
        sha::SHA256(&new_data1, &mut hash_of_new_shard1);

        let new_shard2 = match &self.shard2 {
            RamShard(ram2) => {
                let buf = ram2.unlock(Plain)?;
                let new_data2 = xor(&buf.borrow(), &hash_of_old_shard1, NC_DATA_SIZE);
                let new_data2 = xor(&new_data2, &hash_of_new_shard1, NC_DATA_SIZE);
                RamShard(RamMemory::alloc(&new_data2, NC_DATA_SIZE, Plain)?)
            }
            FileShard(fm) => {
                let buf = fm.unlock(Plain)?;
                let new_data2 = xor(&buf.borrow(), &hash_of_old_shard1, NC_DATA_SIZE);
                let new_data2 = xor(&new_data2, &hash_of_new_shard1, NC_DATA_SIZE);
                let new_fm = FileMemory::alloc(&new_data2, NC_DATA_SIZE, Plain)?;
                FileShard(new_fm)
            }
        };

        Ok(NonContiguousMemory {
            shard1: new_shard1,
            shard2: new_shard2,
            lock: self.lock.clone(),
        })
    }
}

impl<P: BoxProvider> Debug for NonContiguousMemory<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", DEBUG_MSG)
    }
}

//##### Zeroize
impl<P: BoxProvider> Zeroize for MemoryShard<P> {
    fn zeroize(&mut self) {
        match self {
            FileShard(fm) => fm.zeroize(),
            RamShard(buf) => buf.zeroize(),
        }
    }
}

impl<P: BoxProvider> Zeroize for NonContiguousMemory<P> {
    fn zeroize(&mut self) {
        self.shard1.zeroize();
        self.shard2.zeroize();
        self.lock.zeroize();
    }
}

impl<P: BoxProvider> ZeroizeOnDrop for NonContiguousMemory<P> {}

impl<P: BoxProvider> Drop for NonContiguousMemory<P> {
    fn drop(&mut self) {
        self.zeroize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_utils::provider::Provider;

    #[test]
    fn noncontiguous_refresh() {
        let data = Provider::random_vec(NC_DATA_SIZE).unwrap();
        let ncm = NonContiguousMemory::<Provider>::alloc(&data, NC_DATA_SIZE, NonContiguous(NCRamFile));

        assert!(ncm.is_ok());
        let ncm = ncm.unwrap();

        let shard1_before_refresh = ncm.get_buffer_from_shard1();
        let shard2_before_refresh = if let FileShard(fm) = &ncm.shard2 {
            fm.unlock(Plain).unwrap()
        } else {
            panic!("{}", IMPOSSIBLE_CASE)
        };

        let ncm = ncm.refresh();
        assert!(ncm.is_ok());
        let ncm = ncm.unwrap();

        let shard1_after_refresh = ncm.get_buffer_from_shard1();
        let shard2_after_refresh = if let FileShard(fm) = &ncm.shard2 {
            fm.unlock(Plain).unwrap()
        } else {
            panic!("{}", IMPOSSIBLE_CASE)
        };

        // Check that secrets is still ok after refresh
        let buf = ncm.unlock(NonContiguous(NCRamFile));
        assert!(buf.is_ok());
        let buf = buf.unwrap();
        assert_eq!((&*buf.borrow()), &data);

        // Check that refresh change the shards
        assert_ne!(&*shard1_before_refresh.borrow(), &*shard1_after_refresh.borrow());
        assert_ne!(&*shard2_before_refresh.borrow(), &*shard2_after_refresh.borrow());
    }

    #[test]
    // Checking that the shards don't contain the data
    fn boojum_security() {
        // With full Ram
        let data = Provider::random_vec(NC_DATA_SIZE).unwrap();
        let ncm = NonContiguousMemory::<Provider>::alloc(&data, NC_DATA_SIZE, NonContiguous(NCRam));
        assert!(ncm.is_ok());
        let ncm = ncm.unwrap();

        if let RamShard(ram1) = &ncm.shard1 {
            let buf = ram1.unlock(Plain).unwrap();
            assert_ne!(&*buf.borrow(), &data);
        }
        if let RamShard(ram2) = &ncm.shard2 {
            let buf = ram2.unlock(Plain).unwrap();
            assert_ne!(&*buf.borrow(), &data);
        }

        // With Ram and File
        let data = Provider::random_vec(NC_DATA_SIZE).unwrap();
        let ncm = NonContiguousMemory::<Provider>::alloc(&data, NC_DATA_SIZE, NonContiguous(NCRamFile));

        assert!(ncm.is_ok());
        let ncm = ncm.unwrap();

        if let RamShard(ram1) = &ncm.shard1 {
            let buf = ram1.unlock(Plain).unwrap();
            assert_ne!(&*buf.borrow(), &data);
        }
        if let FileShard(fm) = &ncm.shard2 {
            let buf = fm.unlock(Plain).unwrap();
            assert_ne!(&*buf.borrow(), &data);
        }
    }

    #[test]
    fn noncontiguous_zeroize() {
        // Check alloc
        let data = Provider::random_vec(NC_DATA_SIZE).unwrap();
        let ncm = NonContiguousMemory::<Provider>::alloc(&data, NC_DATA_SIZE, NonContiguous(NCRamFile));

        assert!(ncm.is_ok());
        let mut ncm = ncm.unwrap();
        ncm.zeroize();

        if let RamShard(ram1) = &ncm.shard1 {
            assert!(ram1.unlock(Plain).is_err());
        }

        if let FileShard(fm) = &ncm.shard2 {
            assert!(fm.unlock(Plain).is_err());
        }
    }
}
