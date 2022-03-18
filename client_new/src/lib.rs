// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! # Stronghold Client Interface

#![allow(unused_variables, unused_imports, dead_code)]

#[cfg(all(feature = "std", feature = "p2p"))]
pub use stronghold_std_p2p;

#[cfg(feature = "std")]
pub use stronghold_std::*;

#[cfg(feature = "std")]
mod stronghold_std {

    pub use crate::{internal::Provider, security::*, types::*, utils::*};
    use std::{collections::HashMap, error::Error, hash::Hash, path::Path, sync::Arc};

    pub type Result<T> = core::result::Result<T, Box<dyn Error>>;

    /// The Stronghold is a secure storage for sensitive data. Secrets that are stored inside
    /// a Stronghold can never be read, but only be accessed via cryptographic procedures. Data inside
    /// a Stronghold is heavily protected by the [`Runtime`] by either being encrypted at rest, having
    /// kernel supplied memory guards, that prevent memory dumps, or a combination of both. The Stronghold
    /// also persists data written into a Stronghold by creating Snapshots of the current state. The
    /// Snapshot itself is encrypted and can be accessed by a key.
    /// TODO: more epic description
    pub struct Stronghold {
        // what fields?
    }

    impl Default for Stronghold {
        fn default() -> Self {
            todo!()
        }
    }

    impl Stronghold {
        fn load_client<P>(&self, client_path: P) -> core::result::Result<Client, ClientError> {
            todo!()
        }
    }

    impl Drop for Stronghold {
        fn drop(&mut self) {}
    }
}

#[cfg(all(feature = "std", feature = "p2p"))]
mod stronghold_std_p2p {

    // p2p impl here
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests;

#[cfg(feature = "std")]
pub mod types;

#[cfg(feature = "std")]
pub mod internal;

#[cfg(feature = "std")]
pub mod security;

#[cfg(feature = "std")]
pub mod procedures;

// is this std?
#[cfg(feature = "std")]
pub mod utils;
