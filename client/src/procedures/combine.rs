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
    fn then<P>(self, proc_1: P) -> ThenProc<Self, P>
    where
        P: ExecProc,
    {
        ThenProc { proc_0: self, proc_1 }
    }
}

impl<P: ExecProc + Sized> ProcCombine for P {}

// ---------------
// === Chain a next procedure P1 that takes Self::OutData as P1::InData
// ---------------

#[derive(Clone, Procedure)]
pub struct ThenProc<P0, P1> {
    #[source_location]
    proc_0: P0,

    #[target_location]
    proc_1: P1,
}

impl<P0, P1> ExecProc for ThenProc<P0, P1>
where
    P0: ExecProc,
    P1: ExecProc,
{
    fn exec<X: ProcExecutor>(self, executor: &mut X, state: &mut ProcState) -> Result<(), anyhow::Error> {
        self.proc_0.exec(executor, state)?;
        self.proc_1.exec(executor, state)
    }
}
