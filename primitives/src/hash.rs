use std::{error::Error, ops::Range};

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct HashInfo {
    pub id: &'static str,
    pub hash_len: usize,
    pub hash_lens: Range<usize>,
}

pub trait Hash {
    fn info(&self) -> HashInfo;
    fn hash(&self, buf: &mut [u8], data: &[u8]) -> Result<usize, Box<dyn Error + 'static>>;
}

pub trait VarLenHash: Hash {
    fn var_len_hash(&self, buf: &mut [u8], data: &[u8]) -> Result<usize, Box<dyn Error + 'static>>;
}
