use std::{error::Error, ops::Range};

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct KeyDervFuncInfo {
    pub id: &'static str,
    pub output_lens: Range<usize>,
    pub key_lens: Range<usize>,
    pub salt_lens: Range<usize>,
    pub info_lens: Range<usize>,
}

pub trait KeyDervFunc {
    fn info(&self) -> KeyDervFuncInfo;
    fn derive(
        &self,
        buf: &mut [u8],
        base_key: &[u8],
        salt: &[u8],
        info: &[u8],
    ) -> Result<(), Box<dyn Error + 'static>>;
}
