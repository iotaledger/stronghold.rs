use crate::rng::{PublicKeyGen, SecretKeyGen};
use std::{error::Error, ops::Range};

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct SignInfo {
    pub id: &'static str,
    pub sig_lens: Range<usize>,
    pub secret_key_lens: Range<usize>,
    pub public_key_lens: Range<usize>,
}

pub trait Sign: SecretKeyGen + PublicKeyGen {
    fn info(&self) -> SignInfo;

    fn sign(
        &self,
        buf: &mut [u8],
        data: &[u8],
        secret_key: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>>;

    fn verify(
        &self,
        data: &[u8],
        sig: &[u8],
        public_key: &[u8],
    ) -> Result<(), Box<dyn Error + 'static>>;
}
