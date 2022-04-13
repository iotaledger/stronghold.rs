// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    derive_record_id, derive_vault_id,
    procedures::{Procedure, ProcedureError, ProcedureOutput, Runner, StrongholdProcedure},
    Client, ClientError, LoadFromPath, Location, Provider, RecordError,
};
use engine::vault::{RecordHint, RecordId, VaultId};
use std::sync::{Arc, RwLock};
use stronghold_utils::random as rand;

pub const DEFAULT_RANDOM_HINT_SIZE: usize = 24;

pub struct ClientVault {
    /// An atomic but inner mutable back reference to the [`Client`]
    pub(crate) client: Client,

    /// The current vault_path
    pub(crate) vault_path: Vec<u8>,
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
        self.client.write_to_vault(&location, payload)?;
        Ok(())
    }

    /// Deletes a secret from the vault
    ///
    /// # Example
    /// ```
    /// ```
    pub fn delete_secret<P>(&self, record_path: P) -> Result<bool, ClientError>
    where
        P: AsRef<[u8]>,
    {
        self.revoke_secret(record_path)?;
        self.cleanup()
    }

    /// Revokes a secrets and marks it as ready for deletion
    ///
    /// # Example
    /// ```
    /// ```
    ///
    /// # FIXME:
    ///
    /// Since the vault path is already present, only a record path should be provided here
    pub fn revoke_secret<P>(&self, record_path: P) -> Result<(), ClientError>
    where
        P: AsRef<[u8]>,
    {
        let location = Location::Generic {
            record_path: record_path.as_ref().to_vec(),
            vault_path: self.vault_path.clone(),
        };
        self.client.revoke_data(&location)?;
        Ok(())
    }

    /// Collects revoked records and deletes them
    ///
    /// # Example
    /// ```
    /// ```
    pub fn cleanup(&self) -> Result<bool, ClientError> {
        let result = self.client.garbage_collect(self.id());

        Ok(result)
    }

    pub fn id(&self) -> VaultId {
        derive_vault_id(self.vault_path.clone())
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

#[cfg(feature = "p2p")]
impl ClientVault {}
