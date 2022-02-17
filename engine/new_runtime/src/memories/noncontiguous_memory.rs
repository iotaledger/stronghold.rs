use crate::memories::buffer::Buffer;
use crate::memories::file_memory::FileMemory;
use crate::crypto_utils::crypto_box::{BoxProvider, Key};
use crate::locked_memory::ProtectedConfiguration::*;
use crate::locked_memory::ProtectedMemory;
use crate::locked_memory::LockedConfiguration::{self, *};
use crate::locked_memory::LockedMemory;
use crate::locked_memory::MemoryError::{self, *};
use crate::types::Bytes;
use crypto::hashes::sha;
use core::fmt::{self, Debug, Formatter};
use zeroize::Zeroize;


static IMPOSSIBLE_CASE: &'static str = "NonContiguousMemory: this case should not happen if allocated properly";

// Currently we only support data of 32 bytes in noncontiguous memory
const NC_DATA_SIZE: usize = 32;

// NONCONTIGUOUS MEMORY
/// Shards of memory which composes a non contiguous memory
enum MemoryShard<T: Zeroize + Bytes, P: BoxProvider> {
    // EncryptedFileShard(FileMemory<P>),
    // EncryptedRamShard(EncryptedRam<P>),
    ZeroedShard(),
    FileShard(FileMemory<P>),
    RamShard(Buffer<T>),
}
use MemoryShard::*;


/// NonContiguousMemory only works on data which size corresponds to the hash primitive we use. In our case we use it to store keys hence the size of the data depends on the chosen box provider
pub struct NonContiguousMemory<P: BoxProvider>
{
    shard1: MemoryShard<u8, P>,
    shard2: MemoryShard<u8, P>,
    config: LockedConfiguration<P>,
}

impl<P: BoxProvider> LockedMemory<u8, P> for NonContiguousMemory<P>
{
    /// Writes the payload into a LockedMemory then locks it
    fn alloc(payload: &[u8], config: LockedConfiguration<P>) -> Result<Self, MemoryError> {
        NonContiguousMemory::check_config(&config)?;
        let random = P::random_vec(NC_DATA_SIZE).expect("Failed to generate random vec");
        let mut digest = [0u8; NC_DATA_SIZE];

        sha::SHA256(&random, &mut digest);
        digest = xor(&digest, payload);

        let buf1 = Buffer::alloc(&random, BufferConfig(NC_DATA_SIZE))?;
        let shard1 = RamShard(buf1);
        let shard2 = match config {
            NCRamAndFileConfig(_) => {
                let fmem = FileMemory::alloc(
                    &digest,
                    FileConfig(Some(NC_DATA_SIZE)))?;
                FileShard(fmem)
            },
            NCRamConfig(_) => {
                let buf2 = Buffer::alloc(&digest, BufferConfig(NC_DATA_SIZE))?;
                RamShard(buf2)
            },
            _ => panic!("{}", IMPOSSIBLE_CASE)
        };
        Ok(NonContiguousMemory { shard1, shard2, config })
    }

    /// Locks the memory and possibly reallocates
    fn lock(mut self, payload: Buffer<u8>, config: LockedConfiguration<P>) -> Result<Self, MemoryError> {
        self.dealloc()?;
        NonContiguousMemory::alloc(&payload.borrow(), config)
    }

    /// Unlocks the memory and returns an unlocked Buffer
    fn unlock(&self, config: LockedConfiguration<P>) -> Result<Buffer<u8>, MemoryError> {

        let mut data1 = [0u8; NC_DATA_SIZE];
        if let RamShard(buf1) = &self.shard1 {
            sha::SHA256(&buf1.borrow(), &mut data1);
        } else {
            panic!("{}", IMPOSSIBLE_CASE);
        }

        let data = match &self.shard2 {
            RamShard(b2) => {
                xor(&data1, &b2.borrow())
            },
            FileShard(fm) => {
                let buf = fm.unlock(FileConfig(None))
                    .expect("Failed to unlock file memory");
                let x = xor(&data1, &buf.borrow()); x
            },
            _ => panic!("{}", IMPOSSIBLE_CASE)

        };
        Buffer::alloc(&data, BufferConfig(NC_DATA_SIZE))
    }
}

impl<P: BoxProvider> NonContiguousMemory<P>
{
    fn check_config(config: &LockedConfiguration<P>) -> Result<(), MemoryError> {
        match config {
            NCRamAndFileConfig(Some(size)) => {
                if *size != NC_DATA_SIZE {
                    Err(NCSizeNotAllowed)
                } else {
                    Ok(())
                }
            },
            NCRamConfig(Some(size)) => {
                if *size != NC_DATA_SIZE  {
                    Err(NCSizeNotAllowed)
                } else {
                    Ok(())
                }
            },
            _ => Err(ConfigurationNotAllowed)
        }
    }
}

fn xor(a: &[u8], b: &[u8]) -> [u8; NC_DATA_SIZE] {
    let mut ouput = [0u8; NC_DATA_SIZE];
    for i in 0..NC_DATA_SIZE {
        ouput[i] = a[i] ^ b[i]
    }
    ouput
}


impl<P: BoxProvider> Debug for NonContiguousMemory<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "hidden")
    }
}

//##### Zeroize
impl<T: Zeroize + Bytes, P: BoxProvider> Zeroize for MemoryShard<T, P> {
    fn zeroize(&mut self) {
        match self {
            ZeroedShard() => (),
            FileShard(fm) => fm.zeroize(),
            RamShard(buf) => buf.zeroize(),
        }
    }
}

impl<P: BoxProvider> Zeroize for NonContiguousMemory<P>
{
    fn zeroize(&mut self) {
        self.shard1.zeroize();
        self.shard2.zeroize();
        self.config = LockedConfiguration::ZeroedConfig();
    }
}

impl<P: BoxProvider> Drop for NonContiguousMemory<P> {
    fn drop(&mut self) {
        self.zeroize();
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_utils::provider::Provider;

    #[test]
    fn test_functionality_full_ram() {
        // Check alloc
        let data = Provider::random_vec(NC_DATA_SIZE).unwrap();
        let ncm = NonContiguousMemory::<Provider>::alloc(&data, NCRamConfig(Some(NC_DATA_SIZE)));
        assert!(ncm.is_ok());
        let ncm = ncm.unwrap();
        let buf = ncm.unlock(NCRamConfig(None));
        assert!(buf.is_ok());
        let buf = buf.unwrap();
        assert_eq!((&*buf.borrow()), &data);

        // Check locking
        let data = Provider::random_vec(NC_DATA_SIZE).unwrap();
        let buf = Buffer::alloc(&data, BufferConfig(NC_DATA_SIZE));
        assert!(buf.is_ok());
        let ncm = ncm.lock(buf.unwrap(), NCRamConfig(Some(NC_DATA_SIZE)));
        assert!(ncm.is_ok());
        let ncm = ncm.unwrap();
        let buf = ncm.unlock(NCRamConfig(None));
        assert!(buf.is_ok());
        let buf = buf.unwrap();
        assert_eq!((&*buf.borrow()), &data);
    }

    #[test]
    fn test_functionality_ram_file() {
        // Check alloc
        let data = Provider::random_vec(NC_DATA_SIZE).unwrap();
        let ncm = NonContiguousMemory::<Provider>::alloc(&data, NCRamAndFileConfig(Some(NC_DATA_SIZE)));
        assert!(ncm.is_ok());
        let ncm = ncm.unwrap();
        let buf = ncm.unlock(NCRamAndFileConfig(None));
        assert!(buf.is_ok());
        let buf = buf.unwrap();
        assert_eq!((&*buf.borrow()), &data);

        // Check locking
        let data = Provider::random_vec(NC_DATA_SIZE).unwrap();
        let buf = Buffer::alloc(&data, BufferConfig(NC_DATA_SIZE));
        assert!(buf.is_ok());
        let ncm = ncm.lock(buf.unwrap(), NCRamAndFileConfig(Some(NC_DATA_SIZE)));
        assert!(ncm.is_ok());
        let ncm = ncm.unwrap();
        let buf = ncm.unlock(NCRamAndFileConfig(None));
        assert!(buf.is_ok());
        let buf = buf.unwrap();
        assert_eq!((&*buf.borrow()), &data);
    }

    #[test]
    // Checking that the shards don't contain the data
    fn test_lock_security() {
        // With full Ram
        let data = Provider::random_vec(NC_DATA_SIZE).unwrap();
        let ncm = NonContiguousMemory::<Provider>::alloc(&data, NCRamConfig(Some(NC_DATA_SIZE)));
        assert!(ncm.is_ok());
        let ncm = ncm.unwrap();

        if let RamShard(buf) = &ncm.shard1 {
            assert_ne!(&*buf.borrow(), &data);
        }
        if let RamShard(buf) = &ncm.shard2 {
            assert_ne!(&*buf.borrow(), &data);
        }

        // With Ram and File
        let data = Provider::random_vec(NC_DATA_SIZE).unwrap();
        let ncm = NonContiguousMemory::<Provider>::alloc(&data, NCRamAndFileConfig(Some(NC_DATA_SIZE)));
        assert!(ncm.is_ok());
        let ncm = ncm.unwrap();

        if let RamShard(buf) = &ncm.shard1 {
            assert_ne!(&*buf.borrow(), &data);
        }
        if let FileShard(fm) = &ncm.shard2 {
            let buf = fm.unlock(FileConfig(None)).unwrap();
            assert_ne!(&*buf.borrow(), &data);
        }
    }

    #[test]
    fn test_zeroize() {
        // Check alloc
        let data = Provider::random_vec(NC_DATA_SIZE).unwrap();
        let ncm = NonContiguousMemory::<Provider>::alloc(&data, NCRamAndFileConfig(Some(NC_DATA_SIZE)));
        assert!(ncm.is_ok());
        let mut ncm = ncm.unwrap();
        ncm.zeroize();

        if let RamShard(buf) = &ncm.shard1 {
            assert_eq!(*buf.borrow(), []);
        }

        if let FileShard(fm) = &ncm.shard2 {
            let buf = fm.unlock(FileConfig(None));
            // We can't unlock a zeroized filememory
            assert!(buf.is_err());
        }
    }

    #[test]
    // Check that file content cannot be read directly
    fn test_security() {}
}
