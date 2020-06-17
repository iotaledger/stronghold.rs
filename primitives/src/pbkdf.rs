use std::{error::Error, ops::Range};

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct PbkdfInfo {
    pub name: &'static str,
    pub output_lens: Range<usize>,
    pub password_lens: Range<usize>,
    pub salt_lens: Range<usize>,
    pub cpu_cost: u64,
    pub cpu_costs: Range<usize>,
    pub memory_cost: u64,
    pub memory_costs: Range<u64>,
    pub parallelism: u64,
    pub parallelisms: Range<u64>,
}

pub trait Pbkdf {
    fn info(&self) -> PbkdfInfo;
    fn derive(
        &self,
        buf: &mut [u8],
        password: &[u8],
        salt: &[u8],
        cpu_cost: u64,
    ) -> Result<(), Box<dyn Error + 'static>>;
}

pub trait StatlessPbkdf: Pbkdf {
    fn derive_statless(
        &self,
        buf: &mut [u8],
        password: &[u8],
        salt: &[u8],
        cpu_cost: u64,
        memory_cost: u64,
        parallelism: u64,
    ) -> Result<(), Box<dyn Error + 'static>>;
}
