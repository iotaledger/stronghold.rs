// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    error::Error,
    sync::{Arc, RwLock},
};

use engine::{
    runtime::memories::buffer::Buffer,
    vault::{BoxProvider, ClientId, DbView, Key, RecordHint, RecordId, VaultId},
};

use zeroize::Zeroizing;

use crate::{
    derive_vault_id,
    procedures::{
        FatalProcedureError, Procedure, ProcedureError, ProcedureOutput, Products, Runner, StrongholdProcedure,
    },
    Client, ClientError, ClientVault, KeyStore, Location, Provider, RecordError, Store, VaultError,
};
use stronghold_utils::random as rand;
pub const DEFAULT_RANDOM_HINT_SIZE: usize = 24;
type ResolvedLocation = (Key<Provider>, VaultId, RecordId);

/// Resolve the given locations into their corresponding vault keys and vault and record ids.
/// We use a macro instead of a function to avoid data races due to locks being
/// dropped at the end of a function
macro_rules! resolve_locations {
    ($client:expr, $locations:expr, $keystore:expr) => {{
        let mut ids: Vec<(Key<Provider>, VaultId, RecordId)> = Vec::with_capacity(N);

        for location in ($locations) {
            let (vault_id, record_id) = location.resolve();
            let key: Key<Provider> = ($keystore)
                .get_key(vault_id)
                .ok_or(VaultError::VaultNotFound(vault_id))?;
            ids.push((key, vault_id, record_id));
        }
        let ids: [(Key<Provider>, VaultId, RecordId); N] =
            <[_; N]>::try_from(ids).expect("ids did not have exactly len N");
        Ok::<[ResolvedLocation; N], VaultError<FatalProcedureError>>(ids)
    }};
}

// ported [`Runner`] impl for [`Client`]
impl Runner for Client {
    fn get_guards<F, T, const N: usize>(
        &self,
        locations: [Location; N],
        f: F,
    ) -> Result<T, VaultError<FatalProcedureError>>
    where
        F: FnOnce([Buffer<u8>; N]) -> Result<T, FatalProcedureError>,
    {
        let mut ret = None;
        let execute_procedure = |guard: [Buffer<u8>; N]| {
            ret = Some(f(guard)?);
            Ok(())
        };

        let keystore = self.keystore.read().map_err(|_| VaultError::LockPoisoned)?;
        let db = self.db.read().map_err(|_| VaultError::LockPoisoned)?;
        let ids: [(Key<Provider>, VaultId, RecordId); N] = resolve_locations!(self, locations, keystore)?;

        let res = db.get_guards(ids, execute_procedure);

        match res {
            Ok(()) => Ok(ret.unwrap()),
            Err(e) => Err(e),
        }
    }

    fn exec_proc<F, T, const N: usize>(
        &self,
        source_locations: [Location; N],
        target_location: &Location,
        f: F,
    ) -> Result<T, VaultError<FatalProcedureError>>
    where
        F: FnOnce([Buffer<u8>; N]) -> Result<Products<T>, FatalProcedureError>,
    {
        let (target_vid, target_rid) = target_location.resolve();

        let execute_procedure = |guards: [Buffer<u8>; N]| {
            let Products { output: plain, secret } = f(guards)?;
            Ok((secret, plain))
        };

        let random_hint = RecordHint::new(rand::variable_bytestring(DEFAULT_RANDOM_HINT_SIZE)).unwrap();

        let mut keystore = self.keystore.write().map_err(|_| VaultError::LockPoisoned)?;
        let mut db = self.db.write().map_err(|_| VaultError::LockPoisoned)?;

        let sources: [(Key<Provider>, VaultId, RecordId); N] = resolve_locations!(self, source_locations, keystore)?;

        if !keystore.vault_exists(target_vid) {
            let key1 = keystore
                .create_key(target_vid)
                .map_err(|_| VaultError::Procedure("failed to generate key from keystore".to_string().into()))?;
            db.init_vault(&key1, target_vid);
        }

        let target_key = keystore
            .get_key(target_vid)
            .ok_or(VaultError::VaultNotFound(target_vid))?;

        db.exec_procedure(
            sources,
            &target_key,
            target_vid,
            target_rid,
            random_hint,
            execute_procedure,
        )
    }

    fn write_to_vault(&self, location: &Location, value: Zeroizing<Vec<u8>>) -> Result<(), RecordError> {
        let (vault_id, record_id) = location.resolve();

        let mut keystore = self.keystore.write().map_err(|_| RecordError::LockPoisoned)?;
        let mut db = self.db.write().map_err(|_| RecordError::LockPoisoned)?;

        if !keystore.vault_exists(vault_id) {
            // The error type mapped to the possible key creation error is semantically incorrect
            let key = keystore.create_key(vault_id).map_err(|_| RecordError::InvalidKey)?;
            db.init_vault(&key, vault_id);
        }
        let random_hint = RecordHint::new(rand::variable_bytestring(DEFAULT_RANDOM_HINT_SIZE)).unwrap();
        let key = keystore.take_key(vault_id).unwrap();
        let res = db.write(&key, vault_id, record_id, &value, random_hint);

        // this should return an error
        keystore
            .get_or_insert_key(vault_id, key)
            .expect("Inserting key into vault failed");
        res
    }

    fn revoke_data(&self, location: &Location) -> Result<(), RecordError> {
        let (vault_id, record_id) = location.resolve();

        let mut keystore = self.keystore.write().map_err(|_| RecordError::LockPoisoned)?;
        let mut db = self.db.write().map_err(|_| RecordError::LockPoisoned)?;

        if let Some(key) = keystore.take_key(vault_id) {
            let res = db.revoke_record(&key, vault_id, record_id);

            // this should return an error
            keystore
                .get_or_insert_key(vault_id, key)
                .expect("Inserting key into vault failed");
            res?;
        }
        Ok(())
    }

    fn garbage_collect(&self, vault_id: VaultId) -> Result<bool, VaultError<FatalProcedureError>> {
        let mut keystore = self.keystore.write().map_err(|_| VaultError::LockPoisoned)?;
        let mut db = self.db.write().map_err(|_| VaultError::LockPoisoned)?;

        let key = match keystore.take_key(vault_id) {
            Some(key) => key,
            None => return Ok(false),
        };
        db.garbage_collect_vault(&key, vault_id);
        keystore
            .get_or_insert_key(vault_id, key)
            .expect("Inserting key into vault failed");
        Ok(true)
    }
}

impl Client {
    /// Applies `f` to the buffer from the given `location`.
    pub(crate) fn get_guard<F, T>(&self, location: &Location, f: F) -> Result<T, VaultError<FatalProcedureError>>
    where
        F: FnOnce(Buffer<u8>) -> Result<T, FatalProcedureError>,
    {
        let (vault_id, record_id) = location.resolve();

        let mut keystore = self.keystore.write().map_err(|_| VaultError::LockPoisoned)?;
        let db = self.db.read().map_err(|_| VaultError::LockPoisoned)?;

        let key = keystore.take_key(vault_id).ok_or(VaultError::VaultNotFound(vault_id))?;

        let mut ret = None;
        let execute_procedure = |guard: Buffer<u8>| {
            ret = Some(f(guard)?);
            Ok(())
        };

        let res = db.get_guard(&key, vault_id, record_id, execute_procedure);

        // this should return an error
        keystore
            .get_or_insert_key(vault_id, key)
            .expect("Inserting key into vault failed");

        match res {
            Ok(()) => Ok(ret.unwrap()),
            Err(e) => Err(e),
        }
    }
}
