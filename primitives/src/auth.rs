use crate::rng::SecretKeyGen;

use std::{error::Error, ops::Range};

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct MessageAuthCodeInfo {
    pub id: &'static str,
    pub one_time: bool,
    pub len: usize,
    pub mac_lens: Range<usize>,
    pub key_lens: Range<usize>,
}

pub trait MessageAuthCode: SecretKeyGen {
    fn info(&self) -> MessageAuthCodeInfo;
    fn auth(
        &self,
        buf: &mut [u8],
        data: &[u8],
        key: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>>;
}

pub trait VarLenMessageAuthCode: MessageAuthCode {
    fn varlen_auth(
        &self,
        buf: &mut [u8],
        data: &[u8],
        key: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>>;
}
