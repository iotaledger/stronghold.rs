// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod registry;
mod secure;
mod snapshot;

pub use self::{
    registry::{
        messages::{GetAllClients, GetClient, GetSnapshot, HasClient, InsertClient, RemoveClient},
        Registry, RegistryError,
    },
    secure::{
        messages as secure_messages, procedures as secure_procedures,
        procedures::{ProcResult, SLIP10DeriveInput},
        SecureClient,
    },
    snapshot::{messages as snapshot_messages, returntypes as snapshot_returntypes},
};

#[cfg(test)]
// this import is intended for testing purposes only, and should not be included
// in any production code.
pub use secure::testing::ReadFromVault;
