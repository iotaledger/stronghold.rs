// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, HashSet};

use actix::Message;
use engine::{
    runtime::GuardedVec,
    vault::{RecordHint, VaultId},
};
mod primitives;
use crate::{actors::SecureClient, Location, SLIP10DeriveInput};
pub use primitives::*;
use stronghold_derive::Procedure;
use stronghold_utils::{test_utils::fresh, GuardDebug};

// ==========================
// Types
// ==========================

#[derive(GuardDebug)]
pub struct Procedure<P> {
    inner: P,
}

impl<P> Procedure<P>
where
    P: ProcedureStep,
{
    pub fn run<R: Runner>(self, runner: &mut R) -> Result<CollectedOutput, anyhow::Error> {
        let mut state = State {
            aggregated_output: HashMap::new(),
            change_log: Vec::new(),
        };
        match self.inner.execute(runner, &mut state) {
            Ok(()) => {
                // Delete temporary records
                Self::revoke_records(runner, state.change_log, true);
                let mut output = HashMap::new();
                for (k, (data, is_temp)) in state.aggregated_output.into_iter() {
                    if !is_temp {
                        output.insert(k, data);
                    }
                }
                Ok(output)
            }
            Err(e) => {
                // Rollback written data
                Self::revoke_records(runner, state.change_log, false);
                Err(e)
            }
        }
    }

    fn revoke_records<R: Runner>(runner: &mut R, logs: Vec<ChangeLog>, remove_only_temp: bool) {
        let mut vaults = HashSet::new();
        for entry in logs {
            if entry.is_temp || !remove_only_temp {
                let (v, _) = SecureClient::resolve_location(&entry.location);
                let _ = runner.revoke_data(&entry.location);
                vaults.insert(v);
            }
        }
        for vault_id in vaults {
            let _ = runner.garbage_collect(vault_id);
        }
    }
}

impl<P> Message for Procedure<P>
where
    P: ProcedureStep + 'static,
{
    type Result = Result<CollectedOutput, anyhow::Error>;
}

pub struct State {
    aggregated_output: HashMap<OutputKey, (Vec<u8>, bool)>,
    change_log: Vec<ChangeLog>,
}

impl State {
    pub fn insert_data(&mut self, key: OutputKey, value: Vec<u8>, is_temp: bool) {
        self.aggregated_output.insert(key, (value, is_temp));
    }

    pub fn get_data(&mut self, key: &OutputKey) -> Result<Vec<u8>, anyhow::Error> {
        self.aggregated_output
            .get(key)
            .map(|(data, _)| data.clone())
            .ok_or_else(|| anyhow::anyhow!("Missing Data"))
    }

    pub fn add_log(&mut self, location: Location, is_temp: bool) {
        let log = ChangeLog { location, is_temp };
        self.change_log.push(log)
    }
}

#[derive(Debug)]
pub struct ChangeLog {
    location: Location,
    is_temp: bool,
}

pub type CollectedOutput = HashMap<OutputKey, Vec<u8>>;

#[derive(Clone, Hash, PartialEq, Eq)]
pub struct OutputKey(String);

impl OutputKey {
    pub fn new<K: ToString>(key: K) -> Self {
        OutputKey(key.to_string())
    }

    pub fn random() -> Self {
        OutputKey(fresh::string())
    }
}

// ==========================
// Traits
// ==========================

pub trait ProcedureStep {
    fn execute<R: Runner>(self, runner: &mut R, state: &mut State) -> Result<(), anyhow::Error>;

    fn build(self) -> Procedure<Self>
    where
        Self: Sized;

    fn then<P>(self, proc_1: P) -> FusedProcedure<Self, P>
    where
        Self: Sized,
        P: ProcedureStep,
    {
        FusedProcedure { proc_0: self, proc_1 }
    }
}

#[derive(Clone, Procedure)]
pub struct FusedProcedure<P0, P1> {
    #[source]
    proc_0: P0,

    #[target]
    proc_1: P1,
}

impl<P0, P1> ProcedureStep for FusedProcedure<P0, P1>
where
    P0: ProcedureStep,
    P1: ProcedureStep,
{
    fn execute<R: Runner>(self, runner: &mut R, state: &mut State) -> Result<(), anyhow::Error> {
        self.proc_0.execute(runner, state)?;
        self.proc_1.execute(runner, state)
    }

    fn build(self) -> Procedure<Self> {
        Procedure { inner: self }
    }
}

pub trait Runner {
    fn get_guard<F, I, O>(&mut self, location0: &Location, f: F, input: I) -> Result<O, anyhow::Error>
    where
        F: FnOnce(I, GuardedVec<u8>) -> Result<O, engine::Error>;

    fn exec_proc<F, I, O>(
        &mut self,
        location0: &Location,
        location1: &Location,
        hint: RecordHint,
        f: F,
        input: I,
    ) -> Result<O, anyhow::Error>
    where
        F: FnOnce(I, GuardedVec<u8>) -> Result<Products<O>, engine::Error>;

    fn write_to_vault(&mut self, location1: &Location, hint: RecordHint, value: Vec<u8>) -> Result<(), anyhow::Error>;

    fn revoke_data(&mut self, location: &Location) -> Result<(), anyhow::Error>;

    fn garbage_collect(&mut self, vault_id: VaultId) -> Result<(), anyhow::Error>;
}

// ==========================
//  Traits for the `Procedure` derive-macro
// ==========================

pub struct Products<T> {
    pub secret: Vec<u8>,
    pub output: T,
}

trait Parse {
    type Input;
    type Output;
    fn parse(self, input: Self::Input) -> Result<Self::Output, engine::Error>;
}

trait Generate {
    type Input;
    type Output;
    fn generate(self, input: Self::Input) -> Result<Products<Self::Output>, engine::Error>;
}

trait Process {
    type Input;
    type Output;
    fn process(self, input: Self::Input, guard: GuardedVec<u8>) -> Result<Products<Self::Output>, engine::Error>;
}

trait Utilize {
    type Input;
    type Output;
    fn utilize(self, input: Self::Input, guard: GuardedVec<u8>) -> Result<Self::Output, engine::Error>;
}

// ==========================
//  Input /  Output info
// ==========================

#[derive(Clone)]
pub enum InputData<T> {
    Key {
        key: OutputKey,
        convert: fn(Vec<u8>) -> Result<T, anyhow::Error>,
    },
    Value(T),
}

#[derive(Clone)]
pub struct InterimProduct<T> {
    pub target: T,
    pub is_temp: bool,
}

pub trait SourceInfo {
    fn source(&self) -> &Location;
    fn source_location_mut(&mut self) -> &mut Location;
}

impl SourceInfo for Location {
    fn source(&self) -> &Location {
        self
    }
    fn source_location_mut(&mut self) -> &mut Location {
        self
    }
}

impl SourceInfo for SLIP10DeriveInput {
    fn source(&self) -> &Location {
        match self {
            SLIP10DeriveInput::Seed(l) => l,
            SLIP10DeriveInput::Key(l) => l,
        }
    }

    fn source_location_mut(&mut self) -> &mut Location {
        match self {
            SLIP10DeriveInput::Seed(l) => l,
            SLIP10DeriveInput::Key(l) => l,
        }
    }
}

pub trait TargetInfo {
    fn target_info(&self) -> &InterimProduct<Target>;
    fn target_info_mut(&mut self) -> &mut InterimProduct<Target>;

    fn target(&self) -> Location {
        self.target_info().target.location.clone()
    }

    fn write_secret(mut self, location: Location, hint: RecordHint) -> Self
    where
        Self: Sized,
    {
        let target = self.target_info_mut();
        target.target = Target { location, hint };
        target.is_temp = false;
        self
    }
}

#[derive(Clone)]
pub struct Target {
    pub location: Location,
    pub hint: RecordHint,
}

impl Target {
    pub fn random() -> Self {
        let location = Location::generic(fresh::bytestring(), fresh::bytestring());
        let hint = RecordHint::new("".to_string()).unwrap();
        Target { location, hint }
    }
}

impl TargetInfo for InterimProduct<Target> {
    fn target_info(&self) -> &InterimProduct<Target> {
        self
    }
    fn target_info_mut(&mut self) -> &mut InterimProduct<Target> {
        self
    }
}

pub trait InputInfo {
    type Input;
    fn input_info(&self) -> &InputData<Self::Input>;
    fn input_info_mut(&mut self) -> &mut InputData<Self::Input>;
}

impl<T> InputInfo for InputData<T>
where
    T: Clone,
{
    type Input = T;
    fn input_info(&self) -> &InputData<Self::Input> {
        self
    }

    fn input_info_mut(&mut self) -> &mut InputData<Self::Input> {
        self
    }
}

pub trait OutputInfo {
    fn output_info(&self) -> &InterimProduct<OutputKey>;
    fn output_info_mut(&mut self) -> &mut InterimProduct<OutputKey>;

    fn output_key(&self) -> OutputKey {
        let o = self.output_info();
        o.target.clone()
    }

    fn store_output(mut self, key: OutputKey) -> Self
    where
        Self: Sized,
    {
        let info = self.output_info_mut();
        info.target = key;
        info.is_temp = false;
        self
    }
}

impl OutputInfo for InterimProduct<OutputKey> {
    fn output_info(&self) -> &InterimProduct<OutputKey> {
        self
    }
    fn output_info_mut(&mut self) -> &mut InterimProduct<OutputKey> {
        self
    }
}
