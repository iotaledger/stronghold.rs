use std::{error::Error, ops::Range};

// key derive function info
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct KeyDervFuncInfo {
    // key derive function id
    pub id: &'static str,
    // supported output lengths
    pub output_lens: Range<usize>,
    // supported key lengths
    pub key_lens: Range<usize>,
    // supported salt lengths
    pub salt_lens: Range<usize>,
    // supported info lengths
    pub info_lens: Range<usize>,
}

// a oneshot stateless key derivation interface
pub trait KeyDervFunc {
    // returns information about the key derivation function
    fn info(&self) -> KeyDervFuncInfo;
    // derive bytes from the base key with salt and info and fills the buffer.
    fn derive(
        &self,
        buf: &mut [u8],
        base_key: &[u8],
        salt: &[u8],
        info: &[u8],
    ) -> Result<(), Box<dyn Error + 'static>>;
}
