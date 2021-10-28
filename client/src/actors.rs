// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "p2p")]
pub mod p2p;
mod registry;
mod secure;
mod snapshot;

#[cfg(feature = "p2p")]
pub use self::registry::messages::{GetNetwork, InsertNetwork, StopNetwork};
#[cfg(test)]
pub use self::secure::testing as secure_testing;
pub use self::{
    registry::{
        messages::{GetAllClients, GetClient, GetSnapshot, GetTarget, RemoveClient, SpawnClient, SwitchTarget},
        Registry,
    },
    secure::{
        messages as secure_messages, procedures as secure_procedures,
        procedures::{ProcResult, SLIP10DeriveInput},
        SecureClient, VaultError,
    },
    snapshot::{messages as snapshot_messages, returntypes as snapshot_returntypes, WriteSnapshot},
};

#[cfg(test)]
// this import is intended for testing purposes only, and should not be included
// in any production code.
pub use secure::testing::ReadFromVault;
