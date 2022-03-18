// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// use crate::{procedures::Runner, Client, Location};

use std::{
    error::Error,
    sync::{Arc, RwLock},
};

use engine::{
    new_runtime::memories::buffer::Buffer,
    vault::{
        BoxProvider, ClientId, DbView, RecordError as EngineRecordError, RecordHint, VaultError as EngineVaultError,
        VaultId,
    },
};

use crate::{
    derive_vault_id,
    procedures::{
        FatalProcedureError, Procedure, ProcedureError, ProcedureOutput, Products, Runner, StrongholdProcedure,
    },
    Client, ClientError, ClientVault, KeyStore, Location, Provider, Store,
};

pub type VaultError<E> = EngineVaultError<<Provider as BoxProvider>::Error, E>;
pub type RecordError = EngineRecordError<<Provider as BoxProvider>::Error>;

// ported [`Runner`] impl for [`Client`]
impl Runner for Client {
    fn get_guard<F, T>(&mut self, location: &Location, f: F) -> Result<T, VaultError<FatalProcedureError>>
    where
        F: FnOnce(Buffer<u8>) -> Result<T, FatalProcedureError>,
    {
        let (vault_id, record_id) = location.resolve();
        let key = self
            .keystore
            .take_key(vault_id)
            .ok_or(VaultError::VaultNotFound(vault_id))?;

        let mut ret = None;
        let execute_procedure = |guard: Buffer<u8>| {
            ret = Some(f(guard)?);
            Ok(())
        };
        let res = self.db.get_guard(&key, vault_id, record_id, execute_procedure);
        self.keystore.insert_key(vault_id, key);

        match res {
            Ok(()) => Ok(ret.unwrap()),
            Err(e) => Err(e),
        }
    }

    fn exec_proc<F, T>(
        &mut self,
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

        let key0 = self.keystore.take_key(vid0).ok_or(VaultError::VaultNotFound(vid0))?;

        let mut ret = None;
        let execute_procedure = |guard: Buffer<u8>| {
            let Products { output: plain, secret } = f(guard)?;
            ret = Some(plain);
            Ok(secret)
        };

        let res;
        if vid0 == vid1 {
            res = self
                .db
                .exec_proc(&key0, vid0, rid0, &key0, vid1, rid1, hint, execute_procedure);
        } else {
            if !self.keystore.vault_exists(vid1) {
                let key1 = self
                    .keystore
                    .create_key(vid1)
                    .ok_or_else(|| VaultError::Procedure("Failed to generate key from keystore".to_string().into()))?;
                self.db.init_vault(&key1, vid1);
            }
            let key1 = self.keystore.take_key(vid1).unwrap();
            res = self
                .db
                .exec_proc(&key0, vid0, rid0, &key1, vid1, rid1, hint, execute_procedure);
            self.keystore.insert_key(vid1, key1);
        }

        self.keystore.insert_key(vid0, key0);

        match res {
            Ok(()) => Ok(ret.unwrap()),
            Err(e) => Err(e),
        }
    }

    fn write_to_vault(&mut self, location: &Location, hint: RecordHint, value: Vec<u8>) -> Result<(), RecordError> {
        let (vault_id, record_id) = location.resolve();
        if !self.keystore.vault_exists(vault_id) {
            // The error type mapped to the possible key creation error is semantically incorrect
            let key = self.keystore.create_key(vault_id).ok_or(RecordError::InvalidKey)?;
            self.db.init_vault(&key, vault_id);
        }
        let key = self.keystore.take_key(vault_id).unwrap();
        let res = self.db.write(&key, vault_id, record_id, &value, hint);
        self.keystore.insert_key(vault_id, key);
        res
    }

    fn revoke_data(&mut self, location: &Location) -> Result<(), RecordError> {
        let (vault_id, record_id) = location.resolve();
        if let Some(key) = self.keystore.take_key(vault_id) {
            let res = self.db.revoke_record(&key, vault_id, record_id);
            self.keystore.insert_key(vault_id, key);
            res?;
        }
        Ok(())
    }

    fn garbage_collect(&mut self, vault_id: VaultId) -> bool {
        let key = match self.keystore.take_key(vault_id) {
            Some(key) => key,
            None => return false,
        };
        self.db.garbage_collect_vault(&key, vault_id);
        self.keystore.insert_key(vault_id, key);
        true
    }
}
