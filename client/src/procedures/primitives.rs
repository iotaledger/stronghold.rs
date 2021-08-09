// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::{BuildProcedure, ExecProc, GetSourceVault, GetTargetVault, ProcExecutor};
use crypto::utils::rand::fill;
use engine::{
    runtime::GuardedVec,
    vault::{RecordHint, RecordId, VaultId},
};
use std::marker::PhantomData;

pub enum CryptoProcedure {
    Slip10Generate {
        size_bytes: usize,
        vault_id_1: VaultId,
        record_id_1: RecordId,
        hint: RecordHint,
    },
}

impl CryptoProcedure {
    pub fn into_proc(self) -> PrimitiveProc<(), (), (), Vec<u8>> {
        match self {
            CryptoProcedure::Slip10Generate {
                size_bytes,
                vault_id_1,
                record_id_1,
                hint,
            } => {
                let f = move |(), ()| {
                    let mut seed = vec![0u8; size_bytes];
                    fill(&mut seed).map_err(|e| anyhow::anyhow!(e))?;
                    Ok((seed, ()))
                };
                Generator::new(f, vault_id_1, record_id_1, hint)
            }
        }
    }
}

// ==========================
// Primitive Proc
// ==========================

pub type ProcFn<DIn, DOut, SIn, SOut> = Box<dyn Send + Fn(SIn, DIn) -> Result<(SOut, DOut), anyhow::Error>>;

pub struct PrimitiveProc<DIn, DOut, SIn, SOut> {
    f: ProcFn<DIn, DOut, SIn, SOut>,
    location_0: Option<(VaultId, RecordId)>,
    location_1: Option<(VaultId, RecordId, RecordHint)>,
    _marker: (PhantomData<DIn>, PhantomData<DOut>, PhantomData<SIn>, PhantomData<SOut>),
}

impl<DOut, SIn, SOut> PrimitiveProc<(), DOut, SIn, SOut>
where
    Self: ExecProc<InData = ()>,
{
    pub fn build(self) -> BuildProcedure<Self> {
        BuildProcedure(self)
    }
}

// ==========================
// Primitive Proc Types
// ==========================

// ---------------
//=== No secret used, create new secret in vault
// ---------------

pub type Generator<DIn, DOut> = PrimitiveProc<DIn, DOut, (), Vec<u8>>;

// impl ExecProc + GetTargetVault for Generator {}

impl<DIn, DOut> Generator<DIn, DOut> {
    pub(crate) fn new<F>(f: F, vault_id_1: VaultId, record_id_1: RecordId, hint: RecordHint) -> Self
    where
        F: Fn((), DIn) -> Result<(Vec<u8>, DOut), anyhow::Error> + 'static + Send,
    {
        Self {
            f: Box::new(f),
            location_0: None,
            location_1: Some((vault_id_1, record_id_1, hint)),
            _marker: (PhantomData, PhantomData, PhantomData, PhantomData),
        }
    }
}

// ---------------
//=== Existing secret used, new secret created
// ---------------

pub type Processor<DIn, DOut> = PrimitiveProc<DIn, DOut, GuardedVec<u8>, Vec<u8>>;

// impl ExecProc + GetSourceVault + GetTargetVault for Processor {}

impl<DIn, DOut> Processor<DIn, DOut> {
    pub(crate) fn new<F>(
        f: F,
        vault_id_0: VaultId,
        record_id_0: RecordId,
        vault_id_1: VaultId,
        record_id_1: RecordId,
        hint: RecordHint,
    ) -> Self
    where
        F: Fn(GuardedVec<u8>, DIn) -> Result<(Vec<u8>, DOut), anyhow::Error> + 'static + Send,
    {
        Self {
            f: Box::new(f),
            location_0: Some((vault_id_0, record_id_0)),
            location_1: Some((vault_id_1, record_id_1, hint)),
            _marker: (PhantomData, PhantomData, PhantomData, PhantomData),
        }
    }
}
// ---------------
//=== Existing secret used, no new secret created
// ---------------

pub type Sink<DIn, DOut> = PrimitiveProc<DIn, DOut, GuardedVec<u8>, ()>;

// impl ExecProc + GetSourceVault for Sink {}

impl<DIn, DOut> Sink<DIn, DOut> {
    pub(crate) fn new<F>(f: F, vault_id_0: VaultId, record_id_0: RecordId) -> Self
    where
        F: Fn(GuardedVec<u8>, DIn) -> Result<((), DOut), anyhow::Error> + 'static + Send,
    {
        Self {
            f: Box::new(f),
            location_0: Some((vault_id_0, record_id_0)),
            location_1: None,
            _marker: (PhantomData, PhantomData, PhantomData, PhantomData),
        }
    }
}

// ==========================
// Trait implementations
// ==========================

impl<DIn, DOut> ExecProc for Generator<DIn, DOut> {
    type InData = DIn;
    type OutData = DOut;

    fn exec<PExe: ProcExecutor>(self, executor: &mut PExe, input: DIn) -> Result<DOut, anyhow::Error> {
        let (vault_id_1, record_id_1, hint) = self.get_target();
        let f = self.f;
        let (write_vault, output) = f((), input)?;
        executor.write_to_vault(vault_id_1, record_id_1, hint, write_vault)?;
        Ok(output)
    }
}

impl<DIn, DOut> ExecProc for Processor<DIn, DOut> {
    type InData = DIn;
    type OutData = DOut;

    fn exec<PExe: ProcExecutor>(self, executor: &mut PExe, input: DIn) -> Result<DOut, anyhow::Error> {
        let (vault_id_0, record_id_0) = self.get_source();
        let (write_vault, output) = executor.exec_on_guarded(vault_id_0, record_id_0, &self.f, input)?;
        let (vault_id_1, record_id_1, hint) = self.get_target();
        executor.write_to_vault(vault_id_1, record_id_1, hint, write_vault)?;
        Ok(output)
    }
}

impl<DIn, DOut> ExecProc for Sink<DIn, DOut> {
    type InData = DIn;
    type OutData = DOut;

    fn exec<PExe: ProcExecutor>(self, executor: &mut PExe, input: DIn) -> Result<DOut, anyhow::Error> {
        let (vault_id_0, record_id_0) = self.get_source();
        let ((), output) = executor.exec_on_guarded(vault_id_0, record_id_0, &self.f, input)?;
        Ok(output)
    }
}

// A PrimitiveProc<_, _, _, GuardedVec<u8>, _> can only be created via Processor::new or Sink::new, in both cases there
// is a location_0 / source-vault.
impl<DIn, DOut, SOut> GetSourceVault for PrimitiveProc<DIn, DOut, GuardedVec<u8>, SOut> {
    fn get_source(&self) -> (VaultId, RecordId) {
        self.location_0.unwrap()
    }
}

// A PrimitiveProc<_, _, _, _, Vec<u8>> can only be created via Generator::new or Processor::new, in both cases there is
// a location_1 / target-vault.
impl<DIn, DOut, SIn> GetTargetVault for PrimitiveProc<DIn, DOut, SIn, Vec<u8>> {
    fn get_target(&self) -> (VaultId, RecordId, RecordHint) {
        self.location_1.unwrap()
    }
}
