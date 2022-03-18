// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
use crate::{
    procedures::{Procedure, ProcedureError, ProcedureOutput, StrongholdProcedure},
    Result,
};

/// Thin layer over [`engine::Vault`]
pub struct Vault {}

impl Vault {
    /// Writes a secret into the vault
    pub async fn write_secret(&self, location: Vec<u8>, payload: Vec<u8>, hint: Vec<u8>) {
        todo!()
    }

    /// Deletes a secret from the vault
    pub async fn delete_secret(&self, location: Vec<u8>) {
        todo!()
    }

    pub async fn revoke_secret(&self, location: Vec<u8>) {
        todo!()
    }

    pub async fn garbage_collect(&self) {
        todo!()
    }
}
