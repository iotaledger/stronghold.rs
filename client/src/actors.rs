// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "p2p")]
mod p2p;
mod registry;
mod secure;
mod snapshot;

#[cfg(feature = "p2p")]
pub use self::{
    p2p::{messages as network_messages, NetworkActor, NetworkConfig},
    registry::p2p_messages::{GetNetwork, InsertNetwork, RemoveNetwork},
};
pub use self::{
    registry::{
        messages::{GetAllClients, GetClient, GetSnapshot, GetTarget, RemoveClient, SpawnClient, SwitchTarget},
        Registry,
    },
    secure::{messages as secure_messages, RecordError, VaultError},
    snapshot::{messages as snapshot_messages, returntypes as snapshot_returntypes},
};
#[cfg(test)]
pub use secure::testing as secure_testing;
