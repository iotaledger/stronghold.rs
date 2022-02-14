use crate::locked_memory::MemoryError::{self, *};
use crate::locked_memory::ProtectedConfiguration::{self, *};
use crate::locked_memory::ProtectedMemory;
use crate::types::{Bytes, ContiguousBytes};
use core::fmt::{self, Debug, Formatter};
use rand_ascii::distributions::Alphanumeric;
use rand_ascii::{thread_rng, Rng};
use std::fs::{self, File};
use std::io::prelude::*;
use zeroize::Zeroize;

fn main() {
    let rand_string: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect();

    println!("{}", rand_string);
}
const FILENAME_SIZE: usize = 16;

/// File memory
pub struct FileMemory {
    // Filename are random string of 16 characters
    fname: String,
    config: ProtectedConfiguration,
}

impl FileMemory {
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
    fn write_to_file(payload: &[u8]) -> Result<String, std::io::Error> {
        let fname: String = FileMemory::random_fname();
        let mut file = File::create(&fname)?;
        file.write_all(payload.as_bytes())?;
        Ok(fname)
    }

    fn clear_and_delete_file(&self) -> Result<(), std::io::Error> {
        let mut file = File::create(&self.fname)?;
        if let FileConfig(size) = self.config {
            // Zeroes out the file
            file.write_all(&vec![0; size])?;
            // Remove file
            fs::remove_file(&self.fname)
        } else {
            panic!("Case should not happen if FileMemory was allocated properly")
        }
    }
}

impl<T: Bytes> ProtectedMemory<T> for FileMemory {
    fn alloc(payload: &[T], config: ProtectedConfiguration) -> Result<Self, MemoryError> {
        match config {
            FileConfig(_) => {
                let fname = FileMemory::write_to_file(payload.as_bytes()).or(Err(FileSystemError))?;
                Ok(FileMemory { fname, config })
            }

            // We don't allow any other configurations for Buffer
            _ => Err(ConfigurationNotAllowed),
        }
    }
}

impl Zeroize for FileMemory {
    fn zeroize(&mut self) {
        self.clear_and_delete_file();
        self.fname = String::new();
        self.config = ProtectedConfiguration::ZeroedConfig();
    }
}

impl Debug for FileMemory {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        write!(fmt, "{{ config: {:?}, fname: hidden }}", self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init() {
        let buf = Buffer::<u64>::alloc(&[1, 2, 3, 4, 5, 6][..], BufferConfig(6));
        assert!(buf.is_ok());
        assert_eq!((*buf.unwrap().borrow()), [1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn test_zeroize() {}

    #[test]
    fn test_security() {}
}
