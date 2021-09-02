// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::Location;
use engine::vault::RecordHint;
use stronghold_derive::Procedure;

// ==========================
// Combine Trait
// ==========================

pub trait ProcCombine: ExecProc + Sized {
    fn then<P>(self, proc_1: P) -> ProcAndThen<Self, P>
    where
        P: ExecProc,
        P::InData: From<Self::OutData>,
    {
        ProcAndThen { proc_0: self, proc_1 }
    }

    fn reduce<P, F, T>(self, other: P, f: F) -> ProcReduce<Self, P, F>
    where
        Self: ExecProc<InData = ()>,
        P: ExecProc<InData = ()>,
        F: FnOnce(Self::OutData, P::OutData) -> T,
    {
        ProcReduce {
            proc_0: self,
            proc_1: other,
            f,
        }
    }

    fn map_output<F, T>(self, f: F) -> ProcMap<Self, F>
    where
        F: FnOnce(Self::OutData) -> T,
    {
        ProcMap { proc: self, f }
    }

    fn drop_output(self) -> ProcMap<Self, fn(Self::OutData) -> ()> {
        ProcMap {
            proc: self,
            f: |o| drop(o),
        }
    }

    fn on_vec(self) -> ProcIter<Self>
    where
        Self: Clone,
    {
        ProcIter { proc: self }
    }

    fn input<T>(self, data: T) -> ProcAndThen<Input<T>, Self>
    where
        T: Into<Self::InData>,
    {
        let input_proc = Input { data };
        ProcAndThen {
            proc_0: input_proc,
            proc_1: self,
        }
    }

    fn write_output(self, location: Location, hint: RecordHint) -> ProcAndThen<Self, WriteVaultDyn>
    where
        Self::OutData: Into<Vec<u8>>,
    {
        let write_vault_proc = WriteVaultDyn {
            output: (location, hint),
        };
        ProcAndThen {
            proc_0: self,
            proc_1: write_vault_proc,
        }
    }
}

impl<P: ExecProc + Sized> ProcCombine for P {}

// ---------------
// === Perform Procedure on multiple input values
// ---------------

#[derive(Clone, Procedure)]
pub struct ProcIter<P> {
    #[source_location]
    #[target_location]
    proc: P,
}

impl<P> ExecProc for ProcIter<P>
where
    P: ExecProc + Clone,
{
    type InData = Vec<P::InData>;
    type OutData = Vec<P::OutData>;

    fn exec<X: ProcExecutor>(self, executor: &mut X, input: Self::InData) -> Result<Self::OutData, anyhow::Error> {
        input.into_iter().map(|i| self.proc.clone().exec(executor, i)).collect()
    }
}

// ---------------
// === Map ExecProc::OutData into a new type
// ---------------
#[derive(Clone, Procedure)]
pub struct ProcMap<P, F> {
    #[source_location]
    #[target_location]
    proc: P,
    f: F,
}

impl<P, F, T> ExecProc for ProcMap<P, F>
where
    P: ExecProc,
    F: FnOnce(P::OutData) -> T,
{
    type InData = P::InData;
    type OutData = T;

    fn exec<X: ProcExecutor>(self, executor: &mut X, input: Self::InData) -> Result<Self::OutData, anyhow::Error> {
        self.proc.exec(executor, input).map(self.f)
    }
}

// ---------------
// === Chain a next procedure P1 that takes Self::OutData as P1::InData
// ---------------

#[derive(Clone, Procedure)]
pub struct ProcAndThen<P0, P1> {
    #[source_location]
    proc_0: P0,

    #[target_location]
    proc_1: P1,
}

impl<P0, P1> ExecProc for ProcAndThen<P0, P1>
where
    P0: ExecProc,
    P1: ExecProc,
    P0::OutData: Into<P1::InData>,
{
    type InData = P0::InData;
    type OutData = P1::OutData;

    fn exec<X: ProcExecutor>(self, executor: &mut X, input: Self::InData) -> Result<Self::OutData, anyhow::Error> {
        let out = self.proc_0.exec(executor, input)?;
        self.proc_1.exec(executor, out.into())
    }
}

// ---------------
// === Reduce the Result of two Procedures to one
// ---------------

#[derive(Clone, Procedure)]
pub struct ProcReduce<P0, P1, F> {
    proc_0: P0,
    proc_1: P1,
    f: F,
}

impl<P0, P1, F, T> ExecProc for ProcReduce<P0, P1, F>
where
    P0: ExecProc<InData = ()>,
    P1: ExecProc<InData = ()>,
    F: FnOnce(P0::OutData, P1::OutData) -> T + Send,
{
    type InData = ();
    type OutData = T;

    fn exec<X: ProcExecutor>(self, executor: &mut X, _: Self::InData) -> Result<Self::OutData, anyhow::Error> {
        let out_0 = self.proc_0.exec(executor, ())?;
        let out_1 = self.proc_1.exec(executor, ())?;
        let f = self.f;
        Ok(f(out_0, out_1))
    }
}

// ---------------
// === Write bytes to vault
// ---------------

#[derive(Clone, Procedure)]
pub struct ProcWriteVault<P> {
    #[source_location]
    proc: P,

    #[target_location]
    output: (Location, RecordHint),
}

impl<P> ExecProc for ProcWriteVault<P>
where
    P: ExecProc,
    P::OutData: Into<Vec<u8>>,
{
    type InData = P::InData;
    type OutData = ();

    fn exec<X: ProcExecutor>(self, executor: &mut X, input: Self::InData) -> Result<Self::OutData, anyhow::Error> {
        let data = self.proc.exec(executor, input)?;
        let (location, hint) = self.output;
        executor.write_to_vault(location, hint, data.into())?;
        Ok(())
    }
}
