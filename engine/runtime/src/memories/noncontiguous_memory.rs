// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// TODO:
// - replace thread based shard refresh with guard type return and functional refresh

#[cfg(not(any(target_os = "android", target_os = "ios")))]
use crate::memories::frag::{Frag, FragStrategy};
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
use zeroize::{Zeroize, Zeroizing};

use serde::{
    de::{Deserialize, Deserializer, SeqAccess, Visitor},
    ser::{Serialize, Serializer},
};

use std::{cell::RefCell, sync::Mutex};

#[allow(dead_code)]
static IMPOSSIBLE_CASE: &str = "NonContiguousMemory: this case should not happen if allocated properly";
static POISONED_LOCK: &str = "NonContiguousMemory potentially in an unsafe state";

// Currently we only support data of 32 bytes in noncontiguous memory
pub const NC_DATA_SIZE: usize = 32;

// For serialization/deserialization we choose this fullram config
pub const NC_CONFIGURATION: NCConfig = FullRam;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum NCConfig {
    FullFile,
    FullRam,
    RamAndFile,
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    FragAllocation(FragStrategy),
}
use NCConfig::*;

// NONCONTIGUOUS MEMORY
/// Shards of memory which composes a non contiguous memory
#[derive(Clone)]
enum MemoryShard {
    File(FileMemory),
    Ram(RamMemory),
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    Frag(Frag<[u8; NC_DATA_SIZE]>),
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
        let (r, mut m) = self.get_shards_data()?;
        let h = &blake2b::Blake2b256::digest(r);
        xor_mut(&mut m, h, NC_DATA_SIZE);

        // Refresh the shards after each use
        self.refresh()?;

        Ok(Buffer::alloc(&m, NC_DATA_SIZE))
    }
}

impl NonContiguousMemory {
    /// Writes the payload into a LockedMemory then locks it
    pub fn alloc(payload: &[u8], size: usize, config: NCConfig) -> Result<Self, MemoryError> {
        if size != NC_DATA_SIZE {
            return Err(NCSizeNotAllowed);
        };
        let random = random_vec(NC_DATA_SIZE);
        let mut digest = blake2b::Blake2b256::digest(&random);
        xor_mut(&mut digest, payload, NC_DATA_SIZE);

        let (shard1, shard2) = MemoryShard::new_shards(&random, &digest, &config)?;

        let mem = NonContiguousMemory {
            shard1: Mutex::new(RefCell::new(shard1)),
            shard2: Mutex::new(RefCell::new(shard2)),
            config,
        };

        Ok(mem)
    }

    // Refresh the shards to increase security, may be called every _n_ seconds or
    // punctually
    pub fn refresh(&self) -> Result<(), MemoryError> {
        let d = random_vec(NC_DATA_SIZE);
        let (mut r, mut m) = self.get_shards_data()?;

        let hr = &blake2b::Blake2b256::digest(&r);
        xor_mut(&mut r, &d, NC_DATA_SIZE);
        let hd = &blake2b::Blake2b256::digest(&r);

        xor_mut(&mut m, hd, NC_DATA_SIZE);
        xor_mut(&mut m, hr, NC_DATA_SIZE);

        let (shard1, shard2) = MemoryShard::new_shards(&r, &m, &self.config)?;

        let m1 = self.shard1.lock().expect(POISONED_LOCK);
        let m2 = self.shard2.lock().expect(POISONED_LOCK);
        m1.replace(shard1);
        m2.replace(shard2);

        Ok(())
    }

    fn get_shards_data(&self) -> Result<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>), MemoryError> {
        let m1 = self.shard1.lock().expect(POISONED_LOCK);
        let m2 = self.shard2.lock().expect(POISONED_LOCK);
        let shard1 = &*m1.borrow();
        let shard2 = &*m2.borrow();
        Ok((shard1.get()?, shard2.get()?))
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

        let (a_ptr, b_ptr) = match (a, b) {
            (Ram(a), Ram(b)) => (a.get_ptr_address(), b.get_ptr_address()),
            (Frag(a), Frag(b)) => (
                a.get()? as *const [u8; NC_DATA_SIZE] as usize,
                b.get()? as *const [u8; NC_DATA_SIZE] as usize,
            ),
            _ => {
                return Err(MemoryError::Allocation(
                    "Cannot get pointers. Unsupported MemoryShard configuration".to_owned(),
                ));
            }
        };

        Ok((a_ptr, b_ptr))
    }
}

impl MemoryShard {
    fn new_shards(data1: &[u8], data2: &[u8], config: &NCConfig) -> Result<(Self, Self), MemoryError> {
        match config {
            RamAndFile => {
                let ram = RamMemory::alloc(data1, NC_DATA_SIZE)?;
                let fmem = FileMemory::alloc(data2, NC_DATA_SIZE)?;
                Ok((Ram(ram), File(fmem)))
            }

            FullRam => {
                let ram1 = RamMemory::alloc(data1, NC_DATA_SIZE)?;
                let ram2 = RamMemory::alloc(data2, NC_DATA_SIZE)?;
                Ok((Ram(ram1), Ram(ram2)))
            }

            FullFile => {
                let fmem1 = FileMemory::alloc(data1, NC_DATA_SIZE)?;
                let fmem2 = FileMemory::alloc(data2, NC_DATA_SIZE)?;
                Ok((File(fmem1), File(fmem2)))
            }

            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            FragAllocation(strat) => {
                let (frag1, frag2) = Frag::alloc_initialized(
                    *strat,
                    data1.try_into().map_err(|_| MemoryError::NCSizeNotAllowed)?,
                    data2.try_into().map_err(|_| MemoryError::NCSizeNotAllowed)?,
                )?;
                Ok((Frag(frag1), Frag(frag2)))
            }
        }
    }

    fn get(&self) -> Result<Zeroizing<Vec<u8>>, MemoryError> {
        match self {
            File(fm) => {
                let buf = fm.unlock()?;
                let v = buf.borrow().to_vec().into();
                Ok(v)
            }
            Ram(ram) => {
                let buf = ram.unlock()?;
                let v = buf.borrow().to_vec().into();
                Ok(v)
            }
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            Frag(frag) => {
                if frag.is_live() {
                    Ok(frag.get()?.to_vec().into())
                } else {
                    Err(IllegalZeroizedUsage)
                }
            }
        }
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
            File(fm) => fm.zeroize(),
            Ram(buf) => buf.zeroize(),
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            Frag(frag) => frag.zeroize(),
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

    static ERR: &str = "Error while testing non-contiguous memory ";

    const NC_CONFIGS: [NCConfig; 6] = [
        FullFile,
        RamAndFile,
        FullRam,
        FragAllocation(FragStrategy::Map),
        FragAllocation(FragStrategy::Direct),
        FragAllocation(FragStrategy::Hybrid),
    ];

    #[test]
    fn test_ncm_refresh() {
        let data = random_vec(NC_DATA_SIZE);
        for config in NC_CONFIGS {
            println!("config: {:?}", config);
            let ncm = NonContiguousMemory::alloc(&data, NC_DATA_SIZE, config).expect(ERR);
            test_refresh(ncm, &data);
        }
    }

    fn test_refresh(ncm: NonContiguousMemory, original_data: &[u8]) {
        let (data1_before_refresh, data2_before_refresh) = ncm.get_shards_data().expect(ERR);

        assert!(ncm.refresh().is_ok());

        let (data1_after_refresh, data2_after_refresh) = ncm.get_shards_data().expect(ERR);

        // Check that secrets is still ok after refresh
        let buf = ncm.unlock();
        assert!(buf.is_ok());
        let buf = buf.unwrap();
        assert_eq!((*buf.borrow()), *original_data);

        // Check that refresh have changed the shards
        assert_ne!(data1_before_refresh, data1_after_refresh);
        assert_ne!(data2_before_refresh, data2_after_refresh);
    }

    #[test]
    // Checking that the shards don't contain the data
    fn test_ncm_boojum_security() {
        let original_data = random_vec(NC_DATA_SIZE);
        for config in NC_CONFIGS {
            let ncm = NonContiguousMemory::alloc(&original_data, NC_DATA_SIZE, config).expect(ERR);
            let (data1, data2) = ncm.get_shards_data().expect(ERR);
            assert_ne!(data1, original_data);
            assert_ne!(data2, original_data);
        }
    }

    #[test]
    fn test_ncm_zeroize() {
        let data = random_vec(NC_DATA_SIZE);
        for config in NC_CONFIGS {
            let mut ncm = NonContiguousMemory::alloc(&data, NC_DATA_SIZE, config).expect(ERR);
            ncm.zeroize();
            assert!(ncm.get_shards_data().is_err());
        }
    }

    #[test]
    fn test_distance_between_shards() {
        // NCM configurations which are full ram
        let configs = [
            FullRam,
            FragAllocation(FragStrategy::Map),
            FragAllocation(FragStrategy::Direct),
            FragAllocation(FragStrategy::Hybrid),
        ];
        let data = random_vec(NC_DATA_SIZE);

        for config in configs {
            let ncm = NonContiguousMemory::alloc(&data, NC_DATA_SIZE, config).expect(ERR);
            let ptrs = ncm.get_ptr_addresses().expect(ERR);
            let (a, b) = ptrs;
            let distance = a.abs_diff(b);
            assert!(
                distance >= crate::memories::frag::FRAG_MIN_DISTANCE,
                "Pointer distance below threshold: 0x{:08X}",
                distance
            );
        }
    }
}
