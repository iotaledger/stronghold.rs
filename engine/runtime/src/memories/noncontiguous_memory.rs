// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// TODO:
// - replace thread based shard refresh with guard type return and functional refresh

use crate::{
    locked_memory::LockedMemory,
    memories::{buffer::Buffer, file_memory::FileMemory, ram_memory::RamMemory},
    utils::*,
    MemoryError::*,
    *,
};
use core::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
};

// use crypto::hashes::sha;
use crypto::hashes::{blake2b, Digest};
use zeroize::Zeroize;

use serde::{
    de::{Deserialize, Deserializer, SeqAccess, Visitor},
    ser::{Serialize, Serializer},
};

use std::{cell::RefCell, sync::Mutex};

static IMPOSSIBLE_CASE: &str = "NonContiguousMemory: this case should not happen if allocated properly";
static POISONED_LOCK: &str = "NonContiguousMemory potentially in an unsafe state";

// Currently we only support data of 32 bytes in noncontiguous memory
pub const NC_DATA_SIZE: usize = 32;

// Temporary, we currently only use non contiguous with the two shards in RAM
pub const NC_CONFIGURATION: NCConfig = FullRam;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum NCConfig {
    FullFile,
    FullRam,
    RamAndFile,
}
use NCConfig::*;

// NONCONTIGUOUS MEMORY
/// Shards of memory which composes a non contiguous memory
#[derive(Clone)]
enum MemoryShard {
    FileShard(FileMemory),
    RamShard(RamMemory),
}
use MemoryShard::*;

/// NonContiguousMemory only works on data which size corresponds to the hash primitive we use. In our case we use it to
/// store keys hence the size of the data depends on the chosen box provider
pub struct NonContiguousMemory {
    shard1: Mutex<RefCell<MemoryShard>>,
    shard2: Mutex<RefCell<MemoryShard>>,
    config: NCConfig,
}

impl Clone for NonContiguousMemory {
    fn clone(&self) -> Self {
        let mut1 = self.shard1.lock().expect(POISONED_LOCK);
        let mut2 = self.shard2.lock().expect(POISONED_LOCK);
        NonContiguousMemory {
            shard1: Mutex::new(mut1.clone()),
            shard2: Mutex::new(mut2.clone()),
            config: self.config.clone(),
        }
    }
}

impl LockedMemory for NonContiguousMemory {
    /// Locks the memory and possibly reallocates
    fn update(self, payload: Buffer<u8>, size: usize) -> Result<Self, MemoryError> {
        NonContiguousMemory::alloc(&payload.borrow(), size, self.config.clone())
    }

    /// Unlocks the memory and returns an unlocked Buffer
    /// To retrieve secret value you xor the hash contained in shard1 with value in shard2
    fn unlock(&self) -> Result<Buffer<u8>, MemoryError> {
        let data1 = blake2b::Blake2b256::digest(&self.get_buffer_from_shard1().borrow());

        let mut2 = self.shard2.lock().expect(POISONED_LOCK);
        let data = match &*mut2.borrow() {
            RamShard(ram2) => {
                let buf = ram2.unlock()?;
                let x = xor(&data1, &buf.borrow(), NC_DATA_SIZE);
                x
            }
            FileShard(fm) => {
                let buf = fm.unlock()?;
                let x = xor(&data1, &buf.borrow(), NC_DATA_SIZE);
                x
            }
        };
        drop(mut2);

        // Refresh the shards after each use
        self.refresh()?;

        Ok(Buffer::alloc(&data, NC_DATA_SIZE))
    }
}

impl NonContiguousMemory {
    /// Writes the payload into a LockedMemory then locks it
    pub fn alloc(payload: &[u8], size: usize, config: NCConfig) -> Result<Self, MemoryError> {
        if size != NC_DATA_SIZE {
            return Err(NCSizeNotAllowed);
        };
        let random = random_vec(NC_DATA_SIZE);
        let digest = blake2b::Blake2b256::digest(&random);
        let digest = xor(&digest, payload, NC_DATA_SIZE);

        let ram1 = RamMemory::alloc(&random, NC_DATA_SIZE)?;

        let shard1 = RamShard(ram1);

        let shard2 = match config {
            RamAndFile => {
                let fmem = FileMemory::alloc(&digest, NC_DATA_SIZE)?;
                FileShard(fmem)
            }
            FullRam => {
                let ram2 = RamMemory::alloc(&digest, NC_DATA_SIZE)?;
                RamShard(ram2)
            }
            // Not supported yet TODO
            _ => {
                return Err(LockNotAvailable);
            }
        };

        let mem = NonContiguousMemory {
            shard1: Mutex::new(RefCell::new(shard1)),
            shard2: Mutex::new(RefCell::new(shard2)),
            config,
        };

        Ok(mem)
    }

    fn get_buffer_from_shard1(&self) -> Buffer<u8> {
        let mut1 = self.shard1.lock().expect(POISONED_LOCK);
        let shard1 = &*mut1.borrow();

        match shard1 {
            RamShard(ram) => ram.unlock().expect("Failed to retrieve buffer from Ram shard"),
            _ => unreachable!("{}", IMPOSSIBLE_CASE),
        }
    }

    // Refresh the shards to increase security, may be called every _n_ seconds or
    // punctually
    fn refresh(&self) -> Result<(), MemoryError> {
        let random = random_vec(NC_DATA_SIZE);

        // Refresh shard1
        let buf_of_old_shard1 = self.get_buffer_from_shard1();

        let data_of_old_shard1 = &buf_of_old_shard1.borrow();

        let new_data1 = xor(data_of_old_shard1, &random, NC_DATA_SIZE);
        let new_shard1 = RamShard(RamMemory::alloc(&new_data1, NC_DATA_SIZE)?);

        let hash_of_old_shard1 = blake2b::Blake2b256::digest(data_of_old_shard1);
        let hash_of_new_shard1 = blake2b::Blake2b256::digest(&new_data1);

        let mut2 = self.shard2.lock().expect(POISONED_LOCK);
        let new_shard2 = match &*mut2.borrow() {
            RamShard(ram2) => {
                let buf = ram2.unlock()?;
                let new_data2 = xor(&buf.borrow(), &hash_of_old_shard1, NC_DATA_SIZE);
                let new_data2 = xor(&new_data2, &hash_of_new_shard1, NC_DATA_SIZE);
                RamShard(RamMemory::alloc(&new_data2, NC_DATA_SIZE)?)
            }
            FileShard(fm) => {
                let buf = fm.unlock()?;
                let new_data2 = xor(&buf.borrow(), &hash_of_old_shard1, NC_DATA_SIZE);
                let new_data2 = xor(&new_data2, &hash_of_new_shard1, NC_DATA_SIZE);
                let new_fm = FileMemory::alloc(&new_data2, NC_DATA_SIZE)?;
                FileShard(new_fm)
            }
        };

        let mut1 = self.shard1.lock().expect(POISONED_LOCK);
        mut1.replace(new_shard1);
        mut2.replace(new_shard2);

        Ok(())
    }

    /// Returns the memory addresses of the two inner shards.
    ///
    /// This is for testing purposes only, and is intended to work with `NCConfig::FullRam`
    /// only.
    #[cfg(test)]
    pub fn get_ptr_addresses(&self) -> Result<(usize, usize), MemoryError> {
        let muta = self.shard1.lock().expect(POISONED_LOCK);
        let mutb = self.shard2.lock().expect(POISONED_LOCK);
        let a = &*muta.borrow();
        let b = &*mutb.borrow();

        if let (MemoryShard::RamShard(a), MemoryShard::RamShard(b)) = (a, b) {
            let a_ptr = a.get_ptr_address();
            let b_ptr = b.get_ptr_address();

            return Ok((a_ptr, b_ptr));
        }

        Err(MemoryError::Allocation(
            "Cannot get pointers. Unsupported MemoryShard configuration".to_owned(),
        ))
    }
}

impl Debug for NonContiguousMemory {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", DEBUG_MSG)
    }
}

//##### Zeroize
impl Zeroize for MemoryShard {
    fn zeroize(&mut self) {
        match self {
            FileShard(fm) => fm.zeroize(),
            RamShard(buf) => buf.zeroize(),
        }
    }
}

impl Zeroize for NonContiguousMemory {
    fn zeroize(&mut self) {
        let mut1 = self.shard1.lock().expect(POISONED_LOCK);
        let mut2 = self.shard2.lock().expect(POISONED_LOCK);
        mut1.borrow_mut().zeroize();
        mut2.borrow_mut().zeroize();
        self.config = FullRam;
    }
}

impl ZeroizeOnDrop for NonContiguousMemory {}

impl Drop for NonContiguousMemory {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Serialize for NonContiguousMemory {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let buf = self
            .unlock()
            .expect("Failed to unlock NonContiguousMemory for serialization");
        buf.serialize(serializer)
    }
}

struct NonContiguousMemoryVisitor {
    marker: PhantomData<fn() -> NonContiguousMemory>,
}

impl NonContiguousMemoryVisitor {
    fn new() -> Self {
        NonContiguousMemoryVisitor { marker: PhantomData }
    }
}

impl<'de> Visitor<'de> for NonContiguousMemoryVisitor {
    type Value = NonContiguousMemory;

    fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str("NonContiguousMemory not found")
    }

    fn visit_seq<E>(self, mut access: E) -> Result<Self::Value, E::Error>
    where
        E: SeqAccess<'de>,
    {
        let mut seq = Vec::<u8>::with_capacity(access.size_hint().unwrap_or(0));

        while let Some(e) = access.next_element()? {
            seq.push(e);
        }

        let seq = NonContiguousMemory::alloc(seq.as_slice(), seq.len(), NC_CONFIGURATION)
            .expect("Failed to allocate NonContiguousMemory during deserialization");

        Ok(seq)
    }
}

impl<'de> Deserialize<'de> for NonContiguousMemory {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(NonContiguousMemoryVisitor::new())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn noncontiguous_refresh() {
        let data = random_vec(NC_DATA_SIZE);
        let ncm = NonContiguousMemory::alloc(&data, NC_DATA_SIZE, RamAndFile);

        assert!(ncm.is_ok());
        let ncm = ncm.unwrap();

        let shard1_before_refresh = ncm.get_buffer_from_shard1();
        let shard2_before_refresh = if let FileShard(fm) = &*ncm.shard2.lock().expect(POISONED_LOCK).borrow() {
            fm.unlock().unwrap()
        } else {
            panic!("{}", IMPOSSIBLE_CASE)
        };

        assert!(ncm.refresh().is_ok());

        let shard1_after_refresh = ncm.get_buffer_from_shard1();
        let shard2_after_refresh = if let FileShard(fm) = &*ncm.shard2.lock().expect(POISONED_LOCK).borrow() {
            fm.unlock().unwrap()
        } else {
            panic!("{}", IMPOSSIBLE_CASE)
        };

        // Check that secrets is still ok after refresh
        let buf = ncm.unlock();
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
        let data = random_vec(NC_DATA_SIZE);
        let ncm = NonContiguousMemory::alloc(&data, NC_DATA_SIZE, FullRam);
        assert!(ncm.is_ok());
        let ncm = ncm.unwrap();

        if let RamShard(ram1) = &*ncm.shard1.lock().expect(POISONED_LOCK).borrow() {
            let buf = ram1.unlock().unwrap();
            assert_ne!(&*buf.borrow(), &data);
        }
        if let RamShard(ram2) = &*ncm.shard2.lock().expect(POISONED_LOCK).borrow() {
            let buf = ram2.unlock().unwrap();
            assert_ne!(&*buf.borrow(), &data);
        }

        // With Ram and File
        let data = random_vec(NC_DATA_SIZE);
        let ncm = NonContiguousMemory::alloc(&data, NC_DATA_SIZE, RamAndFile);

        assert!(ncm.is_ok());
        let ncm = ncm.unwrap();

        if let RamShard(ram1) = &*ncm.shard1.lock().expect(POISONED_LOCK).borrow() {
            let buf = ram1.unlock().unwrap();
            assert_ne!(&*buf.borrow(), &data);
        }

        if let FileShard(fm) = &*ncm.shard2.lock().expect(POISONED_LOCK).borrow() {
            let buf = fm.unlock().unwrap();
            assert_ne!(&*buf.borrow(), &data);
        };
    }

    #[test]
    fn noncontiguous_zeroize() {
        // Check alloc
        let data = random_vec(NC_DATA_SIZE);
        let ncm = NonContiguousMemory::alloc(&data, NC_DATA_SIZE, RamAndFile);

        assert!(ncm.is_ok());
        let mut ncm = ncm.unwrap();
        ncm.zeroize();

        if let RamShard(ram1) = &*ncm.shard1.lock().expect(POISONED_LOCK).borrow() {
            assert!(ram1.unlock().is_err());
        }

        if let FileShard(fm) = &*ncm.shard2.lock().expect(POISONED_LOCK).borrow() {
            assert!(fm.unlock().is_err());
        };
    }

    #[test]
    fn test_nc_with_alloc() {
        use random::Rng;

        // Usual size for a page
        let threshold = 0x1000;
        let mut payload = [0u8; NC_DATA_SIZE];
        let mut rng = random::thread_rng();
        assert!(rng.try_fill(&mut payload).is_ok(), "Error filling payload bytes");

        let nc = NonContiguousMemory::alloc(&payload, NC_DATA_SIZE, NCConfig::FullRam);
        assert!(nc.is_ok(), "Failed to allocated nc memory");

        let ptrs = nc.unwrap().get_ptr_addresses();
        assert!(ptrs.is_ok());

        let (a, b) = ptrs.unwrap();
        let distance = a.abs_diff(b);
        assert!(
            distance >= threshold,
            "Pointer distance below threshold: 0x{:08X}",
            distance
        );
    }

    // This test is relevant only if the implemented policy is to refresh shards every time we unlock NC memory
    #[test]
    fn test_refresh_on_unlock() {
        use random::Rng;
        let mut payload = [0u8; NC_DATA_SIZE];
        let mut rng = random::thread_rng();
        assert!(rng.try_fill(&mut payload).is_ok(), "Error filling payload bytes");

        let nc = NonContiguousMemory::alloc(&payload, NC_DATA_SIZE, NCConfig::FullRam);
        assert!(nc.is_ok(), "Failed to allocated nc memory");
        let nc = nc.unwrap();

        let ptrs = nc.get_ptr_addresses();
        assert!(ptrs.is_ok());
        let (a, b) = ptrs.unwrap();

        assert!(nc.unlock().is_ok());
        let ptrs = nc.get_ptr_addresses();
        assert!(ptrs.is_ok());
        let (new_a, new_b) = ptrs.unwrap();

        assert_ne!(a, new_a);
        assert_ne!(b, new_b);
    }
}
