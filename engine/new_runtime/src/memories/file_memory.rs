// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    crypto_utils::crypto_box::{BoxProvider, Key},
    locked_memory::{Lock::*, MemoryError::*, *},
    memories::buffer::Buffer,
    types::ContiguousBytes,
};
use core::fmt::{self, Debug, Formatter};
use rand_ascii::{distributions::Alphanumeric, thread_rng, Rng};
use std::{
    fs::{self, File},
    io::prelude::*,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

const FILENAME_SIZE: usize = 16;
const AD_SIZE: usize = 32;

/// File memory
pub struct FileMemory<P: BoxProvider> {
    // Filename are random string of 16 characters
    fname: String,
    lock: Lock<P>,
    // Nonce for encrypted memory
    ad: [u8; AD_SIZE],
    // Size of the decrypted data
    size: usize,
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
        file.write_all(&vec![0; self.size])?;
        // Remove file
        fs::remove_file(&self.fname)
    }
}

impl<P: BoxProvider> LockedMemory<P> for FileMemory<P> {
    fn alloc(payload: &[u8], size: usize, lock: Lock<P>) -> Result<Self, MemoryError> {
        let mut ad: [u8; AD_SIZE] = [0u8; AD_SIZE];
        P::random_buf(&mut ad).or(Err(EncryptionError))?;
        let encrypted: Vec<u8>;
        let (locked_data, _locked_size, lock) = match lock {
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

        let fname = FileMemory::<P>::write_to_file(locked_data.as_bytes()).or(Err(FileSystemError))?;
        Ok(FileMemory { fname, lock, ad, size })
    }

    /// Locks the memory and possibly reallocates
    fn update(self, payload: Buffer<u8>, size: usize, lock: Lock<P>) -> Result<Self, MemoryError> {
        match lock {
            NonContiguous(_) => Err(LockNotAvailable),

            // The current choice is to allocate a completely new file and
            // remove the previous one
            _ => FileMemory::alloc(&payload.borrow(), size, lock),
        }
    }

    /// Unlocks the memory and returns an unlocked Buffer
    fn unlock(&self, lock: Lock<P>) -> Result<Buffer<u8>, MemoryError> {
        // Check that given lock corresponds to ours
        if std::mem::discriminant(&lock) != std::mem::discriminant(&self.lock) {
            return Err(LockNotAvailable);
        }

        let data = self.read_file().or(Err(FileSystemError))?;
        let data = match lock {
            Plain => data,
            Encryption(ref key) => P::box_open(key, &self.ad, &data).or(Err(DecryptionError))?,
            _ => unreachable!("This should not happened if FileMemory has been allocated properly"),
        };
        Ok(Buffer::alloc(&data, self.size))
    }
}

impl<P: BoxProvider> Zeroize for FileMemory<P> {
    // Temporary measure, files get deleted multiple times in non contiguous memory,
    // needs to track usage to improve performance
    #[allow(unused_must_use)]
    fn zeroize(&mut self) {
        self.clear_and_delete_file();
        self.fname.zeroize();
        self.lock.zeroize();
        self.size.zeroize();
        self.ad.zeroize();
    }
}

impl<P: BoxProvider> ZeroizeOnDrop for FileMemory<P> {}

impl<P: BoxProvider> Drop for FileMemory<P> {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl<P: BoxProvider> Debug for FileMemory<P> {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        write!(fmt, "{{ lock: hidden, fname: hidden }}")
    }
}

/// To clone file memory we make a duplicate of the file containing the data
impl<P: BoxProvider> Clone for FileMemory<P> {
    fn clone(&self) -> Self {
        let fname: String = FileMemory::<P>::random_fname();
        fs::copy(&self.fname, &fname).expect("Error in file copy while cloning file memory");
        FileMemory {
            fname,
            lock: self.lock.clone(),
            ad: self.ad,
            size: self.size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_utils::provider::Provider;

    #[test]
    fn test_zeroize() {
        let fm = FileMemory::<Provider>::alloc(&[1, 2, 3, 4, 5, 6][..], 6, Plain);
        assert!(fm.is_ok());
        let mut fm = fm.unwrap();
        let fname = fm.fname.clone();
        fm.zeroize();

        // Check that file has been removed
        assert!(!std::path::Path::new(&fname).exists());
        assert!(fm.fname.is_empty());
        assert_eq!(fm.ad, [0; AD_SIZE]);
    }

    #[test]
    // Check that file content cannot be read directly
    // TODO
    fn test_security() {}
}
