// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/// base Stronghold functionality
mod base;

/// p2p Stronghold functionality
mod p2p;

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

/// re-export base Stronghold functionlity
pub use base::*;

use engine::vault::ClientId;
#[cfg(feature = "p2p")]
pub use p2p::*;

use crate::{Client, ClientError, Snapshot};

/// The Stronghold is a secure storage for sensitive data. Secrets that are stored inside
/// a Stronghold can never be read, but only be accessed via cryptographic procedures. Data inside
/// a Stronghold is heavily protected by the [`Runtime`] by either being encrypted at rest, having
/// kernel supplied memory guards, that prevent memory dumps, or a combination of both. The Stronghold
/// also persists data written into a Stronghold by creating Snapshots of the current state. The
/// Snapshot itself is encrypted and can be accessed by a key.
/// TODO: more epic description
#[derive(Default)]
pub struct Stronghold {
    /// a reference to the [`Snapshot`]
    snapshot: Arc<RwLock<Snapshot>>,

    /// A map of [`ClientId`] to [`Client`]s
    clients: Arc<RwLock<HashMap<ClientId, Client>>>,
}
