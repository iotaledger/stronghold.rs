use std::{error::Error, ops::Range};

/// information block describing the PBKDF implementation.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct PbkdfInfo {
    /// the id of the PBKDF
    pub id: &'static str,
    /// A range of the supported output lengths
    pub output_lens: Range<usize>,
    /// A range of the supported password lengths
    pub password_lens: Range<usize>,
    /// A range of the supported salt lengths
    pub salt_lens: Range<usize>,
    /// the default CPU cost
    pub cpu_cost: u64,
    /// supported CPU costs
    pub cpu_costs: Range<usize>,
    /// the default memory costs
    pub memory_cost: u64,
    /// A range of the supported CPU costs
    pub memory_costs: Range<u64>,
    /// default parallelism which is 0 if PBKDF does not support threading
    pub parallelism: u64,
    /// Range of supported parallelism.
    pub parallelisms: Range<u64>,
}

/// A PBKDF
pub trait Pbkdf {
    /// returns the info of the PBKDF
    fn info(&self) -> PbkdfInfo;
    /// fills the buffer with bytes derived from the password parameterized by the CPU cost.
    fn derive(
        &self,
        buf: &mut [u8],
        password: &[u8],
        salt: &[u8],
        cpu_cost: u64,
    ) -> Result<(), Box<dyn Error + 'static>>;
}

/// A memory hardened PBKDF
pub trait StatelessPbkdf: Pbkdf {
    /// fills the buffer with bytes derived from the password parameterized by the CPU cost.
    fn derive_stateless(
        &self,
        buf: &mut [u8],
        password: &[u8],
        salt: &[u8],
        cpu_cost: u64,
        memory_cost: u64,
        parallelism: u64,
    ) -> Result<(), Box<dyn Error + 'static>>;
}
