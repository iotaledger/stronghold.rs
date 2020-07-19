use std::{error::Error, ops::Range};

/// An information block describing a Hash.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct HashInfo {
    /// A id of hash
    pub id: &'static str,
    /// The hash's length
    pub hash_len: usize,
    /// A range for supported hash lengths
    pub hash_lens: Range<usize>,
}

/// A Hash interface
pub trait Hash {
    /// Get the information block that describes the hash
    fn info(&self) -> HashInfo;
    /// hashes data and returns the hash length. `buf` contains the outgoing hashed data.  
    fn hash(&self, buf: &mut [u8], data: &[u8]) -> Result<usize, Box<dyn Error + 'static>>;
}

/// a variable length hash
pub trait VarLenHash: Hash {
    /// hashes the data and returns the hash length. `buf` contains the outgoing hashed data.
    fn var_len_hash(&self, buf: &mut [u8], data: &[u8]) -> Result<usize, Box<dyn Error + 'static>>;
}
