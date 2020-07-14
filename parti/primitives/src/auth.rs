use crate::rng::SecretKeyGen;

use std::{error::Error, ops::Range};

// Message Authentication Code information block
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct MessageAuthCodeInfo {
    // ID for the MAC
    pub id: &'static str,
    // is the MAC onetime?
    pub one_time: bool,
    // length of the MAC
    pub len: usize,
    // supported MAC lengths
    pub mac_lens: Range<usize>,
    // supported key lengths
    pub key_lens: Range<usize>,
}

// a Message authentication interface that is stateless and oneshot.
pub trait MessageAuthCode: SecretKeyGen {
    // get the info about the MAC
    fn info(&self) -> MessageAuthCodeInfo;
    // authenticate the data using the key.  Returns the MAC length
    fn auth(
        &self,
        buf: &mut [u8],
        data: &[u8],
        key: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>>;
}

// an extension for a variable Message authentication code.
pub trait VarLenMessageAuthCode: MessageAuthCode {
    // authenticates the data using a key.  Returns the MAC's length.
    fn varlen_auth(
        &self,
        buf: &mut [u8],
        data: &[u8],
        key: &[u8],
    ) -> Result<usize, Box<dyn Error + 'static>>;
}
