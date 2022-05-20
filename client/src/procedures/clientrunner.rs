// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    error::Error,
    sync::{Arc, RwLock},
};

use engine::{
    runtime::memories::buffer::Buffer,
    vault::{BoxProvider, ClientId, DbView, Key, RecordHint, RecordId, VaultId},
};

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
        let ids: [(Key<Provider>, VaultId, RecordId); N] = self.resolve_locations(locations)?;

        let mut ret = None;
        let execute_procedure = |guard: [Buffer<u8>; N]| {
            ret = Some(f(guard)?);
            Ok(())
        };

        // FIXME: THIS SHOULD RETURN AN ACTUAL ERROR!
        let db = self.db.try_read().map_err(|e| e.to_string()).expect("");

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
        let sources: [(Key<Provider>, VaultId, RecordId); N] = self.resolve_locations(source_locations)?;
        let (target_vid, target_rid) = target_location.resolve();

        let mut ret = None;
        let execute_procedure = |guards: [Buffer<u8>; N]| {
            let Products { output: plain, secret } = f(guards)?;
            ret = Some(plain);
            Ok(secret)
        };

        let random_hint = RecordHint::new(rand::bytestring(DEFAULT_RANDOM_HINT_SIZE)).unwrap();

        // FIXME: THIS SHOULD RETURN AN ACTUAL ERROR!
        let mut db = self.db.try_write().map_err(|e| e.to_string()).expect("");

        // FIXME: THIS SHOULD RETURN AN ACTUAL ERROR!
        let mut keystore = self.keystore.try_write().map_err(|e| e.to_string()).expect("");

        if !keystore.vault_exists(target_vid) {
            let key1 = keystore
                .create_key(target_vid)
                .map_err(|_| VaultError::Procedure("failed to generate key from keystore".to_string().into()))?;
            db.init_vault(&key1, target_vid);
        }

        let target_key = keystore
            .get_key(target_vid)
            .ok_or(VaultError::VaultNotFound(target_vid))?;

        let res = db.exec_procedure(
            sources,
            &target_key,
            target_vid,
            target_rid,
            random_hint,
            execute_procedure,
        );

        match res {
            Ok(()) => Ok(ret.unwrap()),
            Err(e) => Err(e),
        }
    }

    fn write_to_vault(&self, location: &Location, value: Vec<u8>) -> Result<(), RecordError> {
        let (vault_id, record_id) = location.resolve();

        // FIXME: THIS SHOULD RETURN AN ACTUAL ERROR!
        let mut keystore = self.keystore.try_write().map_err(|e| e.to_string()).expect("");

        // FIXME: THIS SHOULD RETURN AN ACTUAL ERROR!
        let mut db = self.db.try_write().map_err(|e| e.to_string()).expect("");

        if !keystore.vault_exists(vault_id) {
            // The error type mapped to the possible key creation error is semantically incorrect
            let key = keystore.create_key(vault_id).map_err(|_| RecordError::InvalidKey)?;
            db.init_vault(&key, vault_id);
        }
        let random_hint = RecordHint::new(rand::bytestring(DEFAULT_RANDOM_HINT_SIZE)).unwrap();
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

        // FIXME: THIS SHOULD RETURN AN ACTUAL ERROR!
        let mut keystore = self.keystore.try_write().map_err(|e| e.to_string()).expect("");

        // FIXME: THIS SHOULD RETURN AN ACTUAL ERROR!
        let mut db = self.db.try_write().map_err(|e| e.to_string()).expect("");

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

    fn garbage_collect(&self, vault_id: VaultId) -> bool {
        // FIXME: THIS SHOULD RETURN AN ACTUAL ERROR!
        let mut keystore = self.keystore.try_write().map_err(|e| e.to_string()).expect("");

        // FIXME: THIS SHOULD RETURN AN ACTUAL ERROR!
        let mut db = self.db.try_write().map_err(|e| e.to_string()).expect("");

        let key = match keystore.take_key(vault_id) {
            Some(key) => key,
            None => return false,
        };
        db.garbage_collect_vault(&key, vault_id);
        keystore
            .get_or_insert_key(vault_id, key)
            .expect("Inserting key into vault failed");
        true
    }
}

impl Client {
    /// Resolve the given locations into their corresponding vault keys and vault and record ids.
    fn resolve_locations<const N: usize>(
        &self,
        locations: [Location; N],
    ) -> Result<[ResolvedLocation; N], VaultError<FatalProcedureError>> {
        let mut ids: Vec<(Key<Provider>, VaultId, RecordId)> = Vec::with_capacity(N);

        // FIXME: THIS SHOULD RETURN AN ACTUAL ERROR!
        let keystore = self.keystore.try_read().map_err(|e| e.to_string()).expect("");

        for location in locations {
            let (vault_id, record_id) = location.resolve();
            let key: Key<Provider> = keystore.get_key(vault_id).ok_or(VaultError::VaultNotFound(vault_id))?;
            ids.push((key, vault_id, record_id));
        }
        let ids: [(Key<Provider>, VaultId, RecordId); N] =
            <[_; N]>::try_from(ids).expect("ids did not have exactly len N");
        Ok(ids)
    }

    /// Applies `f` to the buffer from the given `location`.
    pub fn get_guard<F, T>(&self, location: &Location, f: F) -> Result<T, VaultError<FatalProcedureError>>
    where
        F: FnOnce(Buffer<u8>) -> Result<T, FatalProcedureError>,
    {
        let (vault_id, record_id) = location.resolve();

        // FIXME: THIS SHOULD RETURN AN ACTUAL ERROR!
        let mut keystore = self.keystore.try_write().map_err(|e| e.to_string()).expect("");

        let key = keystore.take_key(vault_id).ok_or(VaultError::VaultNotFound(vault_id))?;

        let mut ret = None;
        let execute_procedure = |guard: Buffer<u8>| {
            ret = Some(f(guard)?);
            Ok(())
        };
        // FIXME: THIS SHOULD RETURN AN ACTUAL ERROR!
        let db = self.db.try_read().map_err(|e| e.to_string()).expect("");

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
