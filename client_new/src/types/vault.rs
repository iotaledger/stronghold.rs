// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    procedures::{Procedure, ProcedureError, ProcedureOutput, Runner, StrongholdProcedure},
    Client, ClientError, Location, Provider, RecordError,
};
use engine::vault::{RecordHint, VaultId};
use std::sync::{Arc, RwLock};
use stronghold_utils::random as rand;

pub const DEFAULT_RANDOM_HINT_SIZE: usize = 24;

pub struct ClientVault {
    /// An atomic but inner mutable back reference to the [`Client`]
    pub(crate) client: Client,

    /// The current [`VaultId`]
    pub(crate) id: VaultId,
}

/// [`ClientVault`] is a thin abstraction over a vault for a specific [`VaultId`]. An
/// implementation of this type can only be obtained by a [`Client`]. Use the [`ClientVault`]
/// to store secrets and execute [`Procedure`]s on them. Data stored inside a [`Vault`] can
/// never be directly access, nor will its contents ever be exposed.
impl ClientVault {
    /// Writes a secret into the vault
    ///
    /// # Example
    /// ```
    /// ```
    pub fn write_secret(&self, location: Location, payload: Vec<u8>) -> Result<(), ClientError> {
        self.client
            .write_to_vault(
                &location,
                RecordHint::new(rand::bytestring(DEFAULT_RANDOM_HINT_SIZE)).unwrap(),
                payload,
            )
            .map_err(|e| ClientError::Inner(e.to_string()))
    }

    /// Deletes a secret from the vault
    ///
    /// # Example
    /// ```
    /// ```
    pub fn delete_secret(&self, location: Location) -> Result<bool, ClientError> {
        self.revoke_secret(location)?;
        self.cleanup()
    }

    /// Revokes a secrets and marks it as ready for deletion
    ///
    /// # Example
    /// ```
    /// ```
    pub fn revoke_secret(&self, location: Location) -> Result<(), ClientError> {
        self.client
            .revoke_data(&location)
            .map_err(|e| ClientError::Inner(e.to_string()))
    }

    /// Collects revoked records and deletes them
    ///
    /// # Example
    /// ```
    /// ```
    pub fn cleanup(&self) -> Result<bool, ClientError> {
        Ok(self.client.garbage_collect(self.vault_id()))
    }

    /// BUG: this will create confusion, as the vault id, needs to be stored somewhere.
    /// It should be possible to multiple vaults from a client.
    ///
    /// Returns the currently used [`VaultId`]
    ///
    /// # Example
    /// ```
    /// ```
    pub fn vault_id(&self) -> VaultId {
        self.id
    }

    /// SECURITY WARNING! THIS IS FOR TESTING PURPOSES ONLY!
    ///
    /// # Security
    ///
    /// THE CALL TO THIS METHOD IS INSECURE AS IT WILL EXPOSE SECRETS STORED INSIDE A VAULT
    #[cfg(test)]
    pub fn read_secret(&self) {
        todo!()
    }
}
