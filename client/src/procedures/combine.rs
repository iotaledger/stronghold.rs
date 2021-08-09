// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::ops::Deref;

use engine::{
    runtime::GuardedVec,
    vault::{RecordHint, RecordId, VaultId},
};

use super::{BuildProcedure, ExecProc, GetSourceVault, GetTargetVault, ProcExecutor, Processor, Sink};

// ==========================
// Combine Trait
// ==========================

pub trait ProcCombine: ExecProc + Sized {
    fn then_sink<F, OData1>(self, f: F) -> ProcAndThen<Self, Sink<Self::OutData, OData1>>
    where
        Self: GetTargetVault,
        F: Fn(GuardedVec<u8>, Self::OutData) -> Result<((), OData1), anyhow::Error> + 'static + Send,
    {
        let proc_1 = move |v0, r0| Sink::new(f, v0, r0);
        self.and_then(proc_1)
    }

    fn then_process<F, OData1>(
        self,
        f: F,
        vault_id_1: VaultId,
        record_id_1: RecordId,
        hint: RecordHint,
    ) -> ProcAndThen<Self, Processor<Self::OutData, OData1>>
    where
        Self: GetTargetVault,
        F: Fn(GuardedVec<u8>, Self::OutData) -> Result<(Vec<u8>, OData1), anyhow::Error> + 'static + Send,
    {
        let proc_1 = move |v0, r0| Processor::new(f, v0, r0, vault_id_1, record_id_1, hint);
        self.and_then(proc_1)
    }

    fn and_then<P1, F, OData1>(self, f: F) -> ProcAndThen<Self, P1>
    where
        Self: GetTargetVault,
        F: FnOnce(VaultId, RecordId) -> P1,
        P1: ExecProc<InData = Self::OutData, OutData = OData1>,
    {
        let (vault_id, record_id, _) = self.get_target();
        let proc_1 = f(vault_id, record_id);
        ProcAndThen { proc_0: self, proc_1 }
    }

    fn map_output<F, OData1>(self, f: F) -> ProcMap<Self, F>
    where
        F: Fn(Self::OutData) -> OData1,
    {
        ProcMap { proc: self, f }
    }

    fn reduce<P1, F, DOut>(self, other: P1, f: F) -> ProcReduce<Self, P1, F>
    where
        Self: ExecProc<InData = ()>,
        P1: ExecProc<InData = ()>,
        F: FnOnce(Self::OutData, P1::OutData) -> DOut,
    {
        ProcReduce {
            proc_0: self,
            proc_1: other,
            f,
        }
    }
}

impl<P: ExecProc + Sized> ProcCombine for P {}

// ---------------
// === Map ExecProc::OutData into a new type
// ---------------
pub struct ProcMap<P, F> {
    proc: P,
    f: F,
}

impl<P, F, OData1> ProcMap<P, F>
where
    P: ExecProc<InData = ()>,
    F: Fn(P::OutData) -> OData1,
{
    pub fn build(self) -> BuildProcedure<Self> {
        BuildProcedure(self)
    }
}

impl<P, F> Deref for ProcMap<P, F> {
    type Target = P;
    fn deref(&self) -> &Self::Target {
        &self.proc
    }
}

impl<P, F, OData1> ExecProc for ProcMap<P, F>
where
    P: ExecProc,
    F: Fn(P::OutData) -> OData1,
{
    type InData = P::InData;
    type OutData = OData1;

    fn exec<PExe: ProcExecutor>(
        self,
        executor: &mut PExe,
        input: Self::InData,
    ) -> Result<Self::OutData, anyhow::Error> {
        self.proc.exec(executor, input).map(self.f)
    }
}

// ---------------
// === Chain a next procedure P1 that takes Self::OutData as P1::InData
// ---------------

pub struct ProcAndThen<P, P1> {
    proc_0: P,
    proc_1: P1,
}

impl<P, P1> ProcAndThen<P, P1>
where
    P: ExecProc<InData = ()>,
    P1: ExecProc<InData = P::OutData>,
{
    pub fn build(self) -> BuildProcedure<Self> {
        BuildProcedure(self)
    }
}

impl<P, P1> GetSourceVault for ProcAndThen<P, P1>
where
    P: GetSourceVault,
{
    fn get_source(&self) -> (VaultId, RecordId) {
        self.proc_0.get_source()
    }
}

impl<P, P1> GetTargetVault for ProcAndThen<P, P1>
where
    P1: GetTargetVault,
{
    fn get_target(&self) -> (VaultId, RecordId, RecordHint) {
        self.proc_1.get_target()
    }
}

impl<P, P1> ExecProc for ProcAndThen<P, P1>
where
    P: ExecProc,
    P1: ExecProc<InData = P::OutData>,
{
    type InData = P::InData;
    type OutData = P1::OutData;

    fn exec<PExe: ProcExecutor>(
        self,
        executor: &mut PExe,
        input: Self::InData,
    ) -> Result<Self::OutData, anyhow::Error> {
        let out = self.proc_0.exec(executor, input)?;
        self.proc_1.exec(executor, out)
    }
}

// ---------------
// === Reduce the Result of two Procedures to one
// ---------------

pub struct ProcReduce<P, P1, F> {
    proc_0: P,
    proc_1: P1,
    f: F,
}

impl<P, P1, F, DOut> ProcReduce<P, P1, F>
where
    P: ExecProc<InData = ()>,
    P1: ExecProc<InData = ()>,
    F: FnOnce(P::OutData, P1::OutData) -> DOut + Send,
{
    pub fn build(self) -> BuildProcedure<Self> {
        BuildProcedure(self)
    }
}

impl<P, P1, F, DOut> ExecProc for ProcReduce<P, P1, F>
where
    P: ExecProc<InData = ()>,
    P1: ExecProc<InData = ()>,
    F: FnOnce(P::OutData, P1::OutData) -> DOut + Send,
{
    type InData = ();
    type OutData = DOut;

    fn exec<PExe: ProcExecutor>(self, executor: &mut PExe, _: ()) -> Result<Self::OutData, anyhow::Error> {
        let out_0 = self.proc_0.exec(executor, ())?;
        let out_1 = self.proc_1.exec(executor, ())?;
        let f = self.f;
        Ok(f(out_0, out_1))
    }
}
