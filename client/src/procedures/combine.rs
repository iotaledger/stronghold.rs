// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::ops::Deref;

use engine::vault::RecordHint;

use crate::Location;

use super::{BuildProcedure, ExecProc, GetSourceVault, GetTargetVault, ProcExecutor};

// ==========================
// Combine Trait
// ==========================

pub trait ProcCombine: ExecProc + Sized {
    fn and_then<P1>(self, proc_1: P1) -> ProcAndThen<Self, P1>
    where
        P1: ExecProc,
        P1::InData: From<Self::OutData>,
    {
        ProcAndThen { proc_0: self, proc_1 }
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

    fn map_output<F, OData1>(self, f: F) -> ProcMap<Self, F>
    where
        F: FnOnce(Self::OutData) -> OData1,
    {
        ProcMap { proc: self, f }
    }

    fn drop_output(self) -> ProcMap<Self, fn(Self::OutData) -> ()> {
        ProcMap {
            proc: self,
            f: |o| drop(o),
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
    F: FnOnce(P::OutData) -> OData1,
{
    pub fn build(self) -> BuildProcedure<Self> {
        BuildProcedure { inner: self }
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
    F: FnOnce(P::OutData) -> OData1,
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
    P1: ExecProc,
    P1::InData: From<P::OutData>,
{
    pub fn build(self) -> BuildProcedure<Self> {
        BuildProcedure { inner: self }
    }
}

impl<P, P1> GetSourceVault for ProcAndThen<P, P1>
where
    P: GetSourceVault,
{
    fn get_source(&self) -> Location {
        self.proc_0.get_source()
    }
}

impl<P, P1> GetTargetVault for ProcAndThen<P, P1>
where
    P1: GetTargetVault,
{
    fn get_target(&self) -> (Location, RecordHint) {
        self.proc_1.get_target()
    }
}

impl<P, P1> ExecProc for ProcAndThen<P, P1>
where
    P: ExecProc,
    P1: ExecProc,
    P1::InData: From<P::OutData>,
{
    type InData = P::InData;
    type OutData = P1::OutData;

    fn exec<PExe: ProcExecutor>(
        self,
        executor: &mut PExe,
        input: Self::InData,
    ) -> Result<Self::OutData, anyhow::Error> {
        let out = self.proc_0.exec(executor, input)?;
        self.proc_1.exec(executor, out.into())
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
        BuildProcedure { inner: self }
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
