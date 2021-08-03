// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use engine::{
    runtime::GuardedVec,
    vault::{BoxProvider, DbView, Key, RecordHint, RecordId, VaultId},
};

use crate::state::key_store::KeyStore;

struct ProcedureBuilder {
    curr_vault_id: Option<VaultId>,
    curr_record_id: Option<RecordId>,
}

impl ProcedureBuilder {
    fn new() -> Self {
        ProcedureBuilder {
            curr_record_id: None,
            curr_vault_id: None,
        }
    }

    fn switch_vault(mut self, vault_id: VaultId, record_id: RecordId) -> Self {
        self.curr_vault_id = Some(vault_id);
        self.curr_record_id = Some(record_id);
        self
    }

    fn switch_record(mut self, record_id: RecordId) -> Self {
        self.curr_record_id = Some(record_id);
        self
    }

    // abstract from different procedure types
    fn with_proc<P>(mut self, proc: P) -> Self
    where
        P: Proc,
        Self: AsMut<P::Context>,
    {
        let _exec: P::Exec = proc.exec_on_ctx(self.as_mut());
        // add to chain of ExecProcs
        todo!()
    }

    fn flush_state(self) -> Self {
        todo!()
    }

    fn build<'a, Bp>(self) -> Runner<'a, Bp>
    where
        Bp: BoxProvider + Clone + Send + Sync + 'static,
    {
        todo!()
    }
}

trait Proc {
    type Input;
    type Write;
    type Return;
    type Context;
    type Exec: ExecProc<Self::Input, Self::Write, Return = Self::Return>;

    fn exec_on_ctx(self, context: &mut Self::Context) -> Self::Exec;
}

trait ExecProc<I, W> {
    type Return;
    fn exec(self, input: I) -> Result<(W, Self::Return), engine::Error>;
}

struct Runner<'a, Bp: BoxProvider>
where
    Bp: BoxProvider + Clone + Send + Sync + 'static,
{
    db_view: &'a mut DbView<Bp>,
    keystore: &'a mut KeyStore<Bp>,
}

impl<'a, Bp> Runner<'a, Bp>
where
    Bp: BoxProvider + Clone + Send + Sync + 'static,
{
    fn get_source_key(&mut self, vault_id: VaultId) -> Option<Key<Bp>> {
        let key = self.keystore.get_key(vault_id);
        if let Some(pkey) = key.as_ref() {
            self.keystore.insert_key(vault_id, pkey.clone());
        }
        key
    }

    fn get_or_insert_target_key(&mut self, vault_id: VaultId) -> Result<Key<Bp>, anyhow::Error> {
        if !self.keystore.vault_exists(vault_id) {
            let k = self.keystore.create_key(vault_id);
            if let Err(e) = self.db_view.init_vault(&k, vault_id) {
                return Err(anyhow::anyhow!(e));
            };
            Ok(k)
        } else {
            match self.keystore.get_key(vault_id) {
                Some(key) => Ok(key),
                None => {
                    return Err(anyhow::anyhow!("Non existing"));
                }
            }
        }
    }
}

trait RunProc<P: ExecProc<I, W>, I, W> {
    fn run_proc(&mut self, proc: P) -> Result<P::Return, engine::Error>;
}

impl<'a, Bp, P> RunProc<P, GuardedVec<u8>, ()> for Runner<'a, Bp>
where
    Bp: BoxProvider + Clone + Send + Sync + 'static,
    P: ExecProc<GuardedVec<u8>, ()> + ReadSecret,
{
    fn run_proc(&mut self, proc: P) -> Result<P::Return, engine::Error> {
        let (vault_id, record_id) = proc.get_source();
        let key = self
            .get_source_key(vault_id)
            .ok_or(engine::Error::OtherError("Access error".to_string()))?;
        self.keystore.insert_key(vault_id, key.clone());
        let mut ret = None;

        self.db_view.get_guard(&key, vault_id, record_id, |guard| {
            let ((), r) = proc.exec(guard)?;
            ret = Some(r);
            Ok(())
        })?;
        Ok(ret.unwrap())
    }
}

impl<'a, Bp, P> RunProc<P, (), Vec<u8>> for Runner<'a, Bp>
where
    Bp: BoxProvider + Clone + Send + Sync + 'static,
    P: ExecProc<(), Vec<u8>> + WriteVault,
{
    fn run_proc(&mut self, proc: P) -> Result<P::Return, engine::Error> {
        let (vault_id, record_id) = proc.get_target();
        let key = self
            .get_or_insert_target_key(vault_id)
            .map_err(|_| engine::Error::OtherError("Non existing".to_string()))?;

        let hint = proc.get_hint();
        let (write, ret) = proc.exec(())?;

        self.db_view.write(&key, vault_id, record_id, &write, hint)?;
        Ok(ret)
    }
}

impl<'a, Bp, P> RunProc<P, GuardedVec<u8>, Vec<u8>> for Runner<'a, Bp>
where
    Bp: BoxProvider + Clone + Send + Sync + 'static,
    P: ExecProc<GuardedVec<u8>, Vec<u8>> + ReadSecret + WriteVault,
{
    fn run_proc(&mut self, proc: P) -> Result<P::Return, engine::Error> {
        let (src_vault_id, src_record_id) = proc.get_source();
        let src_key = self
            .get_source_key(src_vault_id)
            .ok_or(engine::Error::OtherError("Access error".to_string()))?;

        let (target_vault_id, target_record_id) = proc.get_target();
        let target_key = self
            .get_or_insert_target_key(target_vault_id)
            .map_err(|_| engine::Error::OtherError("Non existing".to_string()))?;

        let hint = proc.get_hint();

        let mut ret = None;

        self.db_view.exec_proc(
            &src_key,
            src_vault_id,
            src_record_id,
            &target_key,
            target_vault_id,
            target_record_id,
            hint,
            |guard| {
                let (w, r) = proc.exec(guard)?;
                ret = Some(r);
                Ok(w)
            },
        )?;
        Ok(ret.unwrap())
    }
}

trait ReadSecret {
    fn get_source(&self) -> (VaultId, RecordId);
}

trait WriteVault {
    fn get_target(&self) -> (VaultId, RecordId);
    fn get_hint(&self) -> RecordHint;
}

// ==========================
// Example
// ==========================

trait Cipher {
    fn encrypt(&self, data: Vec<u8>) -> Vec<u8>;
    fn decrypt(&self, data: Vec<u8>) -> Vec<u8>;
}

impl<T: Cipher> Proc for T {
    type Input = GuardedVec<u8>;
    type Write = ();
    type Return = Vec<u8>;
    type Context = CipherContext;
    type Exec = ExecCipher;

    fn exec_on_ctx(self, context: &mut Self::Context) -> Self::Exec {
        ExecCipher {
            vault_id: context.vault_id.clone(),
            record_id: context.record_id.clone(),
        }
    }
}

struct CipherContext {
    vault_id: VaultId,
    record_id: RecordId,
}

impl AsMut<CipherContext> for ProcedureBuilder {
    fn as_mut(&mut self) -> &mut CipherContext {
        // Provide assurance that vault-id and record-id exist
        let _ctx = CipherContext {
            vault_id: self.curr_vault_id.clone().unwrap(),
            record_id: self.curr_record_id.clone().unwrap(),
        };
        todo!()
    }
}

struct ExecCipher {
    vault_id: VaultId,
    record_id: RecordId,
}

impl ExecProc<GuardedVec<u8>, ()> for ExecCipher {
    type Return = Vec<u8>;
    fn exec(self, _guard: GuardedVec<u8>) -> Result<((), Vec<u8>), engine::Error> {
        todo!();
    }
}

impl ReadSecret for ExecCipher {
    fn get_source(&self) -> (VaultId, RecordId) {
        (self.vault_id.clone(), self.record_id.clone())
    }
}

struct PlainCipher;

impl PlainCipher {
    fn new() -> Self {
        PlainCipher
    }
}

impl Cipher for PlainCipher {
    fn encrypt(&self, data: Vec<u8>) -> Vec<u8> {
        data
    }

    fn decrypt(&self, data: Vec<u8>) -> Vec<u8> {
        data
    }
}

/// Usage

fn main() {
    let _proc = ProcedureBuilder::new().with_proc(PlainCipher::new()).flush_state(); //.build();
                                                                                     // let sh = Stronghold::
                                                                                     // init_stronghold_system(None,
                                                                                     // Vec::new(),
                                                                                     // Vec::new()).unwrap();
                                                                                     // sh.runtime_exec(proc)
}
