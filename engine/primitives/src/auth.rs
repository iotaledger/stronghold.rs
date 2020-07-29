use crate::rng::SecretKeyGen;

use std::{error::Error, ops::Range};

/// Message Authentication Code information block
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct MessageAuthCodeInfo {
    /// the ID for the MAC
    pub id: &'static str,
    /// indicates whether or not the MAC a one shot
    pub one_time: bool,
    /// length of the MAC
    pub len: usize,
    /// A range of the supported MAC lengths
    pub mac_lens: Range<usize>,
    /// A range of the supported key lengths
    pub key_lens: Range<usize>,
}

/// a Message authentication interface (MAC) that is stateless and can be a one shot.
pub trait MessageAuthCode: SecretKeyGen {
    /// get the info about the MAC
    fn info(&self) -> MessageAuthCodeInfo;
    /// authenticate the `data` using the `key` through the `buf` buffer.  Returns the MAC length in a `Result`
    fn auth(&self, buf: &mut [u8], data: &[u8], key: &[u8]) -> Result<usize, Box<dyn Error + 'static>>;
}

/// an extension for a Variable length Message Authentication Code (MAC).
pub trait VarLenMessageAuthCode: MessageAuthCode {
    /// Authenticates the `data` using a `key` through the `buf` buffer.  Returns the MAC's length in a `Result`.
    fn varlen_auth(&self, buf: &mut [u8], data: &[u8], key: &[u8]) -> Result<usize, Box<dyn Error + 'static>>;
}
