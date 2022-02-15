use crate::crypto_utils::crypto_box::{BoxProvider, Key};
use crate::locked_memory::LockedConfiguration::{self, *};
use crate::locked_memory::LockedMemory;
use crate::locked_memory::MemoryError::{self, *};
use crate::locked_memory::{ProtectedConfiguration, ProtectedMemory};
use crate::memories::buffer::Buffer;
use crate::types::{Bytes, ContiguousBytes};
use core::fmt::{self, Debug, Formatter};
use rand_ascii::distributions::Alphanumeric;
use rand_ascii::{thread_rng, Rng};
use std::fs::{self, File};
use std::io::prelude::*;
use zeroize::{Zeroize};

static ERR_SIZE_NONE: &'static str = "FileMemory: the size should not be None if allocated properly";

const FILENAME_SIZE: usize = 16;
const AD_SIZE: usize = 32;

/// File memory
pub struct FileMemory<P: BoxProvider> {
    // Filename are random string of 16 characters
    fname: String,
    config: LockedConfiguration<P>,
    // Nonce for encrypted memory
    ad: [u8; AD_SIZE],
}

impl<P: BoxProvider> FileMemory<P> {
    fn random_fname() -> String {
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(FILENAME_SIZE)
            .map(char::from)
            .collect()
    }

    // TODO: add security
    // - file permissions
    // - noise in the file
    fn read_file(&self) -> Result<Vec<u8>, std::io::Error> {
        fs::read(&self.fname)
    }

    // TODO: add security
    // - file permissions
    // - noise in the file
    fn write_to_file(payload: &[u8]) -> Result<String, std::io::Error> {
        let fname: String = FileMemory::<P>::random_fname();
        let mut file = File::create(&fname)?;
        file.write_all(payload.as_bytes())?;
        Ok(fname)
    }

    fn clear_and_delete_file(&self) -> Result<(), std::io::Error> {
        let mut file = File::create(&self.fname)?;
        // Zeroes out the file
        file.write_all(&vec![0; self.get_data_size()])?;
        // Remove file
        fs::remove_file(&self.fname)
    }

    fn get_data_size(&self) -> usize {
        match self.config {
            FileConfig(size) => size.expect(ERR_SIZE_NONE),
            EncryptedFileConfig(_, size) => size.expect(ERR_SIZE_NONE),
            _ => panic!("{}", ERR_SIZE_NONE),
        }
    }
}

impl<P: BoxProvider> LockedMemory<u8, P> for FileMemory<P> {
    fn alloc(payload: &[u8], config: LockedConfiguration<P>) -> Result<Self, MemoryError> {
        match config {
            // File without encryption
            FileConfig(_) => {
                let fname = FileMemory::<P>::write_to_file(payload.as_bytes()).or(Err(FileSystemError))?;
                Ok(FileMemory {
                    fname,
                    config,
                    ad: [0u8; AD_SIZE],
                })
            }

            // With encryption
            EncryptedFileConfig(key, size) => {
                if size.is_none() {
                    return Err(SizeNeededForAllocation);
                }
                let mut ad: [u8; AD_SIZE] = [0u8; AD_SIZE];
                P::random_buf(&mut ad).or(Err(EncryptionError))?;
                let encrypted_payload = P::box_seal(&key, &ad, payload).or(Err(EncryptionError))?;
                let fname = FileMemory::<P>::write_to_file(&encrypted_payload).or(Err(FileSystemError))?;
                // Don't put the actual key value, put random values,
                // we don't want to store the key
                // for security reasons
                Ok(FileMemory {
                    fname,
                    config: EncryptedFileConfig(Key::random(), size),
                    ad,
                })
            }

            // We don't allow any other configurations for Buffer
            _ => Err(ConfigurationNotAllowed),
        }
    }

    /// Locks the memory and possibly reallocates
    fn lock(mut self, payload: Buffer<u8>, config: LockedConfiguration<P>) -> Result<Self, MemoryError> {
        match config {
            // The current choice is to allocate a completely new file and
            // remove the previous one
            FileConfig(_) => {
                self.dealloc()?;
                FileMemory::alloc(&payload.borrow(), config)
            }

            // The current choice is to allocate a completely new file and
            // remove the previous one
            EncryptedFileConfig(_, _) => {
                self.dealloc()?;
                FileMemory::alloc(&payload.borrow(), config)
            }

            // We don't allow any other configurations for FileMemory
            _ => Err(ConfigurationNotAllowed),
        }
    }

    /// Unlocks the memory and returns an unlocked Buffer
    fn unlock(&self, config: LockedConfiguration<P>) -> Result<Buffer<u8>, MemoryError> {
        // Check if self config and given config matches
        if !self.config.is_eq_config_type(&config) {
            return Err(ConfigurationNotAllowed);
        }

        let mut data = self.read_file().or(Err(FileSystemError))?;

        // If data is encrypted
        if let EncryptedFileConfig(key, _) = config {
            data = P::box_open(&key, &self.ad, &data).or(Err(DecryptionError))?;
        }

        Buffer::alloc(&data, ProtectedConfiguration::BufferConfig(self.get_data_size()))
    }
}

impl<P: BoxProvider> Drop for FileMemory<P> {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl<P: BoxProvider> Zeroize for FileMemory<P> {
    fn zeroize(&mut self) {
        self.clear_and_delete_file();
        self.fname = String::new();
        self.config = ZeroedConfig();
    }
}

impl<P: BoxProvider> Debug for FileMemory<P> {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        write!(fmt, "{{ config: hidden, fname: hidden }}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_utils::provider::Provider;

    #[test]
    fn test_functionality() {
        let fm = FileMemory::<Provider>::alloc(&[1, 2, 3, 4, 5, 6][..], FileConfig(Some(6)));
        assert!(fm.is_ok());
        let fm = fm.unwrap();
        assert!(std::path::Path::new(&fm.fname).exists());
        let buf = fm.unlock(FileConfig(None));
        assert!(buf.is_ok());
        let buf = buf.unwrap();
        assert_eq!((*buf.borrow()), [1, 2, 3, 4, 5, 6]);
        let fm = fm.lock(buf, FileConfig(Some(6)));
        assert!(fm.is_ok());
    }

    #[test]
    fn test_functionality_encryption() {
        let key = Key::random();
        let fm = FileMemory::<Provider>::alloc(&[1, 2, 3, 4, 5, 6][..], EncryptedFileConfig(key.clone(), Some(6)));
        assert!(fm.is_ok());
        let fm = fm.unwrap();
        assert!(std::path::Path::new(&fm.fname).exists());
        let buf = fm.unlock(EncryptedFileConfig(key.clone(), None));
        assert!(buf.is_ok());
        let buf = buf.unwrap();
        assert_eq!((*buf.borrow()), [1, 2, 3, 4, 5, 6]);
        let fm = fm.lock(buf, EncryptedFileConfig(key.clone(), Some(6)));
        assert!(fm.is_ok());
    }

    #[test]
    fn test_zeroize() {
        let fm = FileMemory::<Provider>::alloc(&[1, 2, 3, 4, 5, 6][..], FileConfig(Some(6)));
        assert!(fm.is_ok());
        let mut fm = fm.unwrap();
        let fname = fm.fname.clone();
        fm.zeroize();

        // Check that file has been removed
        assert!(!std::path::Path::new(&fname).exists());
        assert!(fm.fname.is_empty());
        // assert_eq!(fm.config, ZeroedConfig());
    }

    #[test]
    // Check that file content cannot be read directly
    fn test_security() {}
}
