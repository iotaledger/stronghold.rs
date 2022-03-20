// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
use crate::{Client, ClientError};

/// The Stronghold is a secure storage for sensitive data. Secrets that are stored inside
/// a Stronghold can never be read, but only be accessed via cryptographic procedures. Data inside
/// a Stronghold is heavily protected by the [`Runtime`] by either being encrypted at rest, having
/// kernel supplied memory guards, that prevent memory dumps, or a combination of both. The Stronghold
/// also persists data written into a Stronghold by creating Snapshots of the current state. The
/// Snapshot itself is encrypted and can be accessed by a key.
/// TODO: more epic description
#[derive(Default)]
pub struct Stronghold {
    // what fields?
}

// impl Default for Stronghold {
//     fn default() -> Self {
//         Stronghold {}
//     }
// }

impl Stronghold {
    fn load_client<P>(&self, client_path: P) -> core::result::Result<Client, ClientError> {
        todo!()
    }
}

impl Drop for Stronghold {
    fn drop(&mut self) {}
}
