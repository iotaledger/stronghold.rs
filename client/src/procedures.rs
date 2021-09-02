// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use actix::Message;
use engine::{runtime::GuardedVec, vault::RecordHint};
mod combine;
pub use combine::*;
mod primitives;
use crate::Location;
pub use primitives::*;
use stronghold_utils::GuardDebug;

// ==========================
// Traits
// ==========================

#[derive(GuardDebug)]
pub struct ComplexProc<P> {
    inner: P,
}

impl<P> ComplexProc<P>
where
    P: ExecProc<InData = ()>,
{
    pub fn run<X: ProcExecutor>(self, executor: &mut X) -> Result<P::OutData, anyhow::Error> {
        self.inner.exec(executor, ())
    }
}

impl<P> Message for ComplexProc<P>
where
    P: ExecProc<InData = ()> + 'static,
{
    type Result = Result<P::OutData, anyhow::Error>;
}

pub trait BuildProc<P> {
    fn build(self) -> ComplexProc<P>;
}

pub trait ExecProc: BuildProc<Self> + Sized {
    type InData;
    type OutData;

    fn exec<X: ProcExecutor>(self, executor: &mut X, input: Self::InData) -> Result<Self::OutData, anyhow::Error>;
}

pub trait ProcExecutor {
    fn get_guard<F, I, O>(&mut self, location0: Location, f: F, input: I) -> Result<O, anyhow::Error>
    where
        F: FnOnce(I, GuardedVec<u8>) -> Result<O, engine::Error>;

    fn exec_proc<F, I, O>(
        &mut self,
        location0: Location,
        location1: Location,
        hint: RecordHint,
        f: F,
        input: I,
    ) -> Result<O, anyhow::Error>
    where
        F: FnOnce(I, GuardedVec<u8>) -> Result<ProcOutput<O>, engine::Error>;

    fn write_to_vault(&mut self, location1: Location, hint: RecordHint, value: Vec<u8>) -> Result<(), anyhow::Error>;
}

pub trait GetSourceVault {
    fn get_source(&self) -> Location;
}

pub trait GetTargetVault {
    fn get_target(&self) -> (Location, RecordHint);

    fn get_target_location(&self) -> Location {
        let (location, _) = self.get_target();
        location
    }
}

impl GetSourceVault for Location {
    fn get_source(&self) -> Location {
        self.clone()
    }
}

impl GetTargetVault for (Location, RecordHint) {
    fn get_target(&self) -> (Location, RecordHint) {
        self.clone()
    }
}
