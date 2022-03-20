// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    error::Error,
    sync::{Arc, RwLock},
};

use engine::{
    new_runtime::memories::buffer::Buffer,
    vault::{BoxProvider, ClientId, DbView, RecordHint, VaultId},
};

use crate::{
    derive_vault_id,
    procedures::{
        FatalProcedureError, Procedure, ProcedureError, ProcedureOutput, Products, Runner, StrongholdProcedure,
    },
    Client, ClientError, ClientVault, KeyStore, Location, Provider, RecordError, Store, VaultError,
};

// ported [`Runner`] impl for [`Client`]
impl Runner for Client {
    fn get_guard<F, T>(&self, location: &Location, f: F) -> Result<T, VaultError<FatalProcedureError>>
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
        let mut db = self.db.try_write().map_err(|e| e.to_string()).expect("");

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

    fn exec_proc<F, T>(
        &self,
        location0: &Location,
        location1: &Location,
        hint: RecordHint,
        f: F,
    ) -> Result<T, VaultError<FatalProcedureError>>
    where
        F: FnOnce(Buffer<u8>) -> Result<Products<T>, FatalProcedureError>,
    {
        let (vid0, rid0) = location0.resolve();
        let (vid1, rid1) = location1.resolve();
        // FIXME: THIS SHOULD RETURN AN ACTUAL ERROR!
        let mut keystore = self.keystore.try_write().map_err(|e| e.to_string()).expect("");

        let key0 = keystore.take_key(vid0).ok_or(VaultError::VaultNotFound(vid0))?;

        let mut ret = None;
        let execute_procedure = |guard: Buffer<u8>| {
            let Products { output: plain, secret } = f(guard)?;
            ret = Some(plain);
            Ok(secret)
        };

        let res;
        if vid0 == vid1 {
            // FIXME: THIS SHOULD RETURN AN ACTUAL ERROR!
            let mut db = self.db.try_write().map_err(|e| e.to_string()).expect("");

            res = db.exec_proc(&key0, vid0, rid0, &key0, vid1, rid1, hint, execute_procedure);
        } else {
            // FIXME: THIS SHOULD RETURN AN ACTUAL ERROR!
            let mut db = self.db.try_write().map_err(|e| e.to_string()).expect("");

            if !keystore.vault_exists(vid1) {
                let key1 = keystore
                    .create_key(vid1)
                    .map_err(|_| VaultError::Procedure("Failed to generate key from keystore".to_string().into()))?;
                db.init_vault(&key1, vid1);
            }

            let key1 = keystore.take_key(vid1).unwrap();
            res = db.exec_proc(&key0, vid0, rid0, &key1, vid1, rid1, hint, execute_procedure);

            // this should return an error
            keystore
                .get_or_insert_key(vid1, key1)
                .expect("Inserting key into vault failed");
        }

        // this should be an errors
        keystore
            .get_or_insert_key(vid0, key0)
            .expect("Inserting key into vault faileds");

        match res {
            Ok(()) => Ok(ret.unwrap()),
            Err(e) => Err(e),
        }
    }

    fn write_to_vault(&self, location: &Location, hint: RecordHint, value: Vec<u8>) -> Result<(), RecordError> {
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
        let key = keystore.take_key(vault_id).unwrap();
        let res = db.write(&key, vault_id, record_id, &value, hint);

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
