use thiserror::Error as DeriveError;

mod bucket;
mod cache;
mod client;
mod ids;
mod provider;
mod secret;

pub use ids::ClientId;

#[macro_export]
macro_rules! line_error {
    () => {
        concat!("Error at ", file!(), ":", line!())
    };
    ($str:expr) => {
        concat!($str, " @", file!(), ":", line!())
    };
}

pub type Result<T> = anyhow::Result<T, Error>;

#[derive(DeriveError, Debug)]
pub enum Error {
    #[error("Id Error")]
    IDError,
    #[error("Vault Error: {0}")]
    VaultError(#[from] engine::vault::Error),
}
