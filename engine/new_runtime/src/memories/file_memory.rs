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
    os::unix::fs::PermissionsExt,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

const FILENAME_SIZE: usize = 16;
const AD_SIZE: usize = 32;

/// Data is stored into files in clear or encrypted.
/// Basic security of this file includes files access control and
/// TODO noise in the file
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

    fn clear_and_delete_file(&self) -> Result<(), std::io::Error> {
        set_write_only(&self.fname)?;
        let mut file = File::create(&self.fname)?;
        // Zeroes out the file
        file.write_all(&vec![0; self.size])?;
        // Remove file
        fs::remove_file(&self.fname)
    }
}

// TODO: add security
// - file permissions
// - noise in the file
fn read_file(fname: &str) -> Result<Vec<u8>, std::io::Error> {
    set_read_only(fname)?;
    let content = fs::read(fname)?;
    lock_file(fname)?;
    Ok(content)
}

// TODO: add security
// - file permissions
// - noise in the file
fn write_to_file(payload: &[u8], fname: &str) -> Result<(), std::io::Error> {
    match set_write_only(fname) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        err => {
            return err;
        }
    };
    let mut file = File::create(fname)?;
    file.write_all(payload.as_bytes())?;
    lock_file(fname)
}

fn lock_file(path: &str) -> Result<(), std::io::Error> {
    // Lock file permissions
    let mut perms = fs::metadata(path)?.permissions();
    if cfg!(unix) {
        // Prevent reading/writing
        perms.set_mode(0o000);
    } else {
        // Currently rust fs library can only be create
        // readonly file permissions
        perms.set_readonly(true);
    }
    fs::set_permissions(path, perms)
}

fn set_write_only(path: &str) -> Result<(), std::io::Error> {
    // Lock file permissions
    let mut perms = fs::metadata(path)?.permissions();
    if cfg!(unix) {
        // Set write only
        perms.set_mode(0o200);
    } else {
        // Currently rust fs library can only be create
        // readonly file permissions
        perms.set_readonly(true);
    }
    fs::set_permissions(path, perms)
}

fn set_read_only(path: &str) -> Result<(), std::io::Error> {
    // Lock file permissions
    let mut perms = fs::metadata(path)?.permissions();
    if cfg!(unix) {
        // Set write only
        perms.set_mode(0o400);
    } else {
        // Currently rust fs library can only be create
        // readonly file permissions
        perms.set_readonly(true);
    }
    fs::set_permissions(path, perms)
}

impl<P: BoxProvider> LockedMemory<P> for FileMemory<P> {
    fn alloc(payload: &[u8], size: usize, lock: Lock<P>) -> Result<Self, MemoryError> {
        if size == 0 {
            return Err(ZeroSizedNotAllowed);
        }
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

        // Write to file

        let fname: String = FileMemory::<P>::random_fname();
        write_to_file(locked_data.as_bytes(), &fname).or(Err(FileSystemError))?;
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
        if self.size == 0 {
            return Err(ZeroSizedNotAllowed);
        }
        // Check that given lock corresponds to ours
        if std::mem::discriminant(&lock) != std::mem::discriminant(&self.lock) {
            return Err(LockNotAvailable);
        }

        let data = read_file(&self.fname).or(Err(FileSystemError))?;
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
        let error_msg = "Issue while copying file";
        let fname: String = FileMemory::<P>::random_fname();
        set_read_only(&self.fname).expect(error_msg);
        fs::copy(&self.fname, &fname).expect("Error in file copy while cloning file memory");
        lock_file(&self.fname).expect(error_msg);
        lock_file(&fname).expect(error_msg);
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
    fn file_zeroize() {
        let fm = FileMemory::<Provider>::alloc(&[1, 2, 3, 4, 5, 6][..], 6, Plain);
        assert!(fm.is_ok());
        let mut fm = fm.unwrap();
        let fname = fm.fname.clone();
        fm.zeroize();

        // Check that file has been removed
        assert!(!std::path::Path::new(&fname).exists());
        assert!(fm.fname.is_empty());
        assert_eq!(fm.ad, [0; AD_SIZE]);
        assert!(fm.unlock(Plain).is_err());
    }

    #[test]
    // Check that file content cannot be accessed directly
    fn file_security() {
        let fm = FileMemory::<Provider>::alloc(&[1, 2, 3, 4, 5, 6][..], 6, Plain);
        assert!(fm.is_ok());
        let fm = fm.unwrap();

        // Try to read or write file
        let try_read = File::open(&fm.fname).expect_err("Test failed shall gives an Err");
        let try_write = File::create(&fm.fname).expect_err("Test failed shall gives an Err");
        assert_eq!(try_read.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(try_write.kind(), std::io::ErrorKind::PermissionDenied);
    }
}
