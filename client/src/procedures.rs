// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use actix::Message;
use engine::{
    runtime::GuardedVec,
    vault::{RecordHint, VaultId},
};
use std::{
    collections::{HashMap, HashSet},
    convert::{TryFrom, TryInto},
    ops::Deref,
    string::FromUtf8Error,
};
use thiserror::Error as DeriveError;
mod primitives;
use crate::{
    actors::{SecureClient, VaultError},
    Location,
};
pub use primitives::*;
use serde::{Deserialize, Serialize};
use stronghold_utils::{test_utils::fresh::non_empty_bytestring, GuardDebug};

// ==========================
// Types
// ==========================

#[derive(Clone, GuardDebug, Serialize, Deserialize)]
pub struct Procedure {
    inner: Vec<PrimitiveProcedure>,
}

impl Procedure {
    pub fn run<R: Runner>(self, runner: &mut R) -> Result<CollectedOutput, ProcedureError> {
        let mut state = State {
            aggregated_output: HashMap::new(),
            change_log: Vec::new(),
        };
        match self.execute(runner, &mut state) {
            Ok(()) => {
                // Delete temporary records
                Self::revoke_records(runner, state.change_log, true);
                let mut output = HashMap::new();
                for (k, (data, is_temp)) in state.aggregated_output.into_iter() {
                    if !is_temp {
                        output.insert(k, data);
                    }
                }
                Ok(CollectedOutput { output })
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

impl ProcedureStep for Procedure {
    fn execute<R: Runner>(self, runner: &mut R, state: &mut State) -> Result<(), ProcedureError> {
        self.inner.into_iter().try_for_each(|p| p.execute(runner, state))
    }
}

impl Message for Procedure {
    type Result = Result<CollectedOutput, anyhow::Error>;
}

impl<P> From<P> for Procedure
where
    P: Into<PrimitiveProcedure>,
{
    fn from(p: P) -> Self {
        Self { inner: vec![p.into()] }
    }
}

#[derive(DeriveError, Debug)]
pub enum ProcedureError {
    #[error("Invalid Input Type")]
    InvalidInput,

    #[error("Missing Input")]
    MissingInput,

    #[error("Vault Error {0}")]
    VaultError(VaultError),
}

#[derive(Serialize, Deserialize)]
pub struct State {
    aggregated_output: HashMap<OutputKey, (ProcedureIo, bool)>,
    change_log: Vec<ChangeLog>,
}

impl State {
    pub fn insert_data(&mut self, key: OutputKey, value: ProcedureIo, is_temp: bool) {
        self.aggregated_output.insert(key, (value, is_temp));
    }

    pub fn get_data(&self, key: &OutputKey) -> Option<&ProcedureIo> {
        self.aggregated_output.get(key).map(|(data, _)| data)
    }

    pub fn add_log(&mut self, location: Location, is_temp: bool) {
        let log = ChangeLog { location, is_temp };
        self.change_log.push(log)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChangeLog {
    location: Location,
    is_temp: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcedureIo(Vec<u8>);

impl Deref for ProcedureIo {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<u8>> for ProcedureIo {
    fn from(v: Vec<u8>) -> Self {
        ProcedureIo(v)
    }
}

impl From<ProcedureIo> for Vec<u8> {
    fn from(p: ProcedureIo) -> Self {
        p.0
    }
}

impl AsRef<Vec<u8>> for ProcedureIo {
    fn as_ref(&self) -> &Vec<u8> {
        &self.0
    }
}

impl From<String> for ProcedureIo {
    fn from(s: String) -> Self {
        ProcedureIo(s.into_bytes())
    }
}

impl TryFrom<ProcedureIo> for String {
    type Error = FromUtf8Error;
    fn try_from(value: ProcedureIo) -> Result<Self, Self::Error> {
        String::from_utf8(value.0)
    }
}

impl<const N: usize> From<[u8; N]> for ProcedureIo {
    fn from(a: [u8; N]) -> Self {
        ProcedureIo(a.into())
    }
}

impl<const N: usize> TryFrom<ProcedureIo> for [u8; N] {
    type Error = <[u8; N] as TryFrom<Vec<u8>>>::Error;

    fn try_from(value: ProcedureIo) -> Result<Self, Self::Error> {
        value.0.try_into()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CollectedOutput {
    output: HashMap<OutputKey, ProcedureIo>,
}

impl CollectedOutput {
    pub fn take<T>(&mut self, key: &OutputKey) -> Option<T>
    where
        ProcedureIo: TryInto<T>,
    {
        self.output.remove(key).and_then(|v| v.try_into().ok())
    }
}

impl IntoIterator for CollectedOutput {
    type IntoIter = <HashMap<OutputKey, ProcedureIo> as IntoIterator>::IntoIter;
    type Item = <HashMap<OutputKey, ProcedureIo> as IntoIterator>::Item;
    fn into_iter(self) -> Self::IntoIter {
        self.output.into_iter()
    }
}

#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OutputKey(String);

impl OutputKey {
    pub fn new<K: ToString>(key: K) -> Self {
        OutputKey(key.to_string())
    }

    pub fn random() -> Self {
        OutputKey(rand::random::<char>().into())
    }
}

// ==========================
// Traits
// ==========================

pub trait ProcedureStep {
    fn execute<R: Runner>(self, runner: &mut R, state: &mut State) -> Result<(), ProcedureError>;

    fn then<P>(self, next: P) -> Procedure
    where
        Self: Into<Procedure>,
        P: Into<Procedure>,
    {
        let mut procedure = self.into();
        procedure.inner.extend(next.into().inner);
        procedure
    }
}

pub trait Runner {
    fn get_guard<F, T>(&mut self, location0: &Location, f: F) -> Result<T, VaultError>
    where
        F: FnOnce(GuardedVec<u8>) -> Result<T, engine::Error>;

    fn exec_proc<F, T>(
        &mut self,
        location0: &Location,
        location1: &Location,
        hint: RecordHint,
        f: F,
    ) -> Result<T, VaultError>
    where
        F: FnOnce(GuardedVec<u8>) -> Result<Products<T>, engine::Error>;

    fn write_to_vault(&mut self, location1: &Location, hint: RecordHint, value: Vec<u8>) -> Result<(), VaultError>;

    fn revoke_data(&mut self, location: &Location) -> Result<(), VaultError>;

    fn garbage_collect(&mut self, vault_id: VaultId) -> Result<(), VaultError>;
}

// ==========================
//  Traits for the `Procedure` derive-macro
// ==========================

pub struct Products<T> {
    pub secret: Vec<u8>,
    pub output: T,
}

trait ProcessOutput {
    type Input;
    type Output;
    fn process(self, input: Self::Input) -> Result<Self::Output, engine::Error>;
}

trait GenerateSecret {
    type Input;
    type Output;
    fn generate(self, input: Self::Input) -> Result<Products<Self::Output>, engine::Error>;
}

trait DeriveSecret {
    type Input;
    type Output;
    fn derive(self, input: Self::Input, guard: GuardedVec<u8>) -> Result<Products<Self::Output>, engine::Error>;
}

trait UseSecret {
    type Input;
    type Output;
    fn use_secret(self, input: Self::Input, guard: GuardedVec<u8>) -> Result<Self::Output, engine::Error>;
}

// ==========================
//  Input /  Output Info
// ==========================

#[derive(Clone, Serialize, Deserialize)]
pub enum InputData<T>
where
    T: TryFrom<ProcedureIo>,
{
    Key(OutputKey),
    Value(T),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct InterimProduct<T> {
    pub target: T,
    pub is_temp: bool,
}

pub trait SourceInfo {
    fn source_location(&self) -> &Location;
    fn source_location_mut(&mut self) -> &mut Location;
}

impl SourceInfo for Location {
    fn source_location(&self) -> &Location {
        self
    }
    fn source_location_mut(&mut self) -> &mut Location {
        self
    }
}

impl SourceInfo for SLIP10DeriveInput {
    fn source_location(&self) -> &Location {
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

#[derive(Clone, Serialize, Deserialize)]
pub struct Target {
    pub location: Location,
    pub hint: RecordHint,
}

impl Target {
    pub fn random() -> Self {
        let location = Location::generic(non_empty_bytestring(), non_empty_bytestring());
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
    type Input: TryFrom<ProcedureIo>;

    fn input_info(&self) -> &InputData<Self::Input>;
    fn input_info_mut(&mut self) -> &mut InputData<Self::Input>;
}

impl<T> InputInfo for InputData<T>
where
    T: TryFrom<ProcedureIo>,
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
