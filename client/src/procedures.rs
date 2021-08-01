// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use engine::{
    runtime::GuardedVec,
    vault::{BoxProvider, DbView, Key, RecordHint, RecordId, VaultId},
};

use crate::state::key_store::KeyStore;

struct ProcContext<Bp>
where
    Bp: BoxProvider + Clone + Send + Sync + 'static,
{
    view: DbView<Bp>,
    keystore: KeyStore<Bp>,
}

impl<Bp> ProcContext<Bp>
where
    Bp: BoxProvider + Clone + Send + Sync + 'static,
{
    fn create(view: DbView<Bp>, keystore: KeyStore<Bp>) -> Self {
        Self { view, keystore }
    }

    fn switch(mut self, new_view: DbView<Bp>, new_keystore: KeyStore<Bp>) -> Self {
        self.view = new_view;
        self.keystore = new_keystore;
        self
    }
}

trait Proc {
    type Input;
    type Write;
    type Return;

    fn exec(self, input: Self::Input) -> Result<(Self::Write, Self::Return), engine::Error>;
}

trait ExecProc<Bp: BoxProvider>: Proc {
    fn run(self, db_view: &mut DbView<Bp>) -> Result<<Self as Proc>::Return, engine::Error>;
}

impl<'a, Bp, P> ExecProc<Bp> for P
where
    Bp: BoxProvider + 'a,
    P: Proc<Input = ()> + WriteVault<'a, Bp>,
{
    fn run(self, db_view: &mut DbView<Bp>) -> Result<P::Return, anyhow::Error> {
        let (vault_id, record_id) = self.get_target();
        let key = self.get_target_key();

        let hint = self.get_hint();
        let (write, ret) = self.exec(())?;

        db_view.write(&key, vault_id, record_id, &write, hint)?;
        Ok(ret)
    }
}

impl<'a, Bp, P> ExecProc<Bp> for P
where
    Bp: BoxProvider + 'a,
    P: Proc<Write = ()> + ReadSecret<'a, Bp>,
    P::Return: Default,
{
    fn run(self, db_view: &mut DbView<Bp>) -> Result<P::Return, engine::Error> {
        if let Some(key) = self.get_src_key() {
            let (vault_id, record_id) = self.get_source();
            let mut ret = P::Return::default();

            db_view.get_guard(&key, vault_id, record_id, |guard| {
                let ((), r) = self.exec(guard)?;
                ret = r;
                Ok(())
            })?;
            Ok(ret)
        } else {
            Err(anyhow::anyhow!("Failed to access Vault"))
        }
    }
}

impl<'a, Bp, P> ExecProc<Bp> for P
where
    Bp: BoxProvider + 'a,
    P: ReadSecret<'a, Bp> + WriteVault<'a, Bp>,
    P::Return: Default,
{
    fn run(self, db_view: &mut DbView<Bp>) -> Result<P::Return, engine::Error> {
        let (src_vault_id, src_record_id) = self.get_source();
        let src_key = self.get_src_key();

        let (target_vault_id, target_record_id) = self.get_target();
        let target_key = self.get_target_key();

        let hint = self.get_hint();

        let mut ret = P::Return::default();

        db_view.exec_proc(
            src_key,
            src_vault_id,
            src_record_id,
            target_key,
            target_vault_id,
            target_record_id,
            hint,
            |guard| {
                let (w, r) = self.exec(guard)?;
                ret = r;
                Ok(w)
            },
        )?;
        Ok(ret)
    }
}

trait ReadSecret<'a, Bp: BoxProvider>: Proc<Input = GuardedVec<u8>> {
    fn get_source(&self) -> (VaultId, RecordId);
    fn get_src_key(&self) -> &'a Key<Bp>;
}

trait WriteVault<'a, Bp: BoxProvider>: Proc<Write = Vec<u8>> {
    fn get_hint(&self) -> RecordHint;
    fn get_target(&self) -> (VaultId, RecordId);
    fn get_target_key(&self) -> &'a Key<Bp>;
}

struct Plain;

impl Proc for Plain {
    type Input = ();
    type Write = ();
    type Return = String;

    fn exec(self, _: ()) -> Result<(Self::Write, Self::Return), engine::Error> {
        Ok(((), "test".to_string()))
    }
}
