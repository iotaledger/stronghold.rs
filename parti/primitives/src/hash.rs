use std::{error::Error, ops::Range};

// information regarding the Hash implementation.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct HashInfo {
    // id of hash
    pub id: &'static str,
    // hash length
    pub hash_len: usize,
    // supported hash lengths
    pub hash_lens: Range<usize>,
}

// a oneshot and stateless hash interface
pub trait Hash {
    // get information about the hash
    fn info(&self) -> HashInfo;
    // hashes data and returns the hash length
    fn hash(&self, buf: &mut [u8], data: &[u8]) -> Result<usize, Box<dyn Error + 'static>>;
}

// a variable length extension of the hash trait
pub trait VarLenHash: Hash {
    // hashes the data and returns the hash length
    fn var_len_hash(&self, buf: &mut [u8], data: &[u8]) -> Result<usize, Box<dyn Error + 'static>>;
}
