pub use primitives;
use thiserror::Error as DeriveError;

mod internal;
mod poly;

#[derive(DeriveError, Debug)]
pub enum Error {
    #[error("Invalid Data")]
    InvalidData,
    #[error("Interface Error occuring")]
    InterfaceError,
}

pub type Result<T> = std::result::Result<T, Error>;
