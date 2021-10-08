// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::primitives::PrimitiveProcedure;
use crate::{
    actors::{SecureClient, VaultError},
    Location,
};
use actix::Message;
use engine::{
    runtime::GuardedVec,
    vault::{RecordHint, VaultId},
};
use hmac::digest::generic_array::{ArrayLength, GenericArray};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    convert::{Infallible, TryFrom, TryInto},
    ops::Deref,
    string::FromUtf8Error,
};
use stronghold_utils::{test_utils::fresh::non_empty_bytestring, GuardDebug};
use thiserror::Error as DeriveError;

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
            aggregated: TempCollectedOutput {
                temp_output: HashMap::default(),
            },
            change_log: Vec::default(),
        };
        match self.execute(runner, &mut state) {
            Ok(()) => {
                // Delete temporary records
                Self::revoke_records(runner, state.change_log, true);
                Ok(state.aggregated.into())
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

#[derive(Clone, Serialize, Deserialize)]
pub struct CollectedOutput {
    output: HashMap<OutputKey, ProcedureIo>,
}

impl CollectedOutput {
    pub fn take<T>(&mut self, key: &OutputKey) -> Option<T>
    where
        T: TryFromProcedureIo,
    {
        self.output.remove(key).and_then(|v| T::try_from_procedure_io(v).ok())
    }
}

impl IntoIterator for CollectedOutput {
    type IntoIter = <HashMap<OutputKey, ProcedureIo> as IntoIterator>::IntoIter;
    type Item = <HashMap<OutputKey, ProcedureIo> as IntoIterator>::Item;
    fn into_iter(self) -> Self::IntoIter {
        self.output.into_iter()
    }
}

impl From<TempCollectedOutput> for CollectedOutput {
    fn from(temp: TempCollectedOutput) -> Self {
        let output = temp
            .temp_output
            .into_iter()
            .filter_map(|(key, (value, is_temp))| match is_temp {
                true => None,
                false => Some((key, value)),
            })
            .collect();
        CollectedOutput { output }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcedureIo(Vec<u8>);

impl Deref for ProcedureIo {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.0
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
    aggregated: TempCollectedOutput,
    change_log: Vec<ChangeLog>,
}

impl State {
    pub fn insert_output(&mut self, key: OutputKey, value: ProcedureIo, is_temp: bool) {
        self.aggregated.temp_output.insert(key, (value, is_temp));
    }

    pub fn get_output(&self, key: &OutputKey) -> Option<&ProcedureIo> {
        self.aggregated.temp_output.get(key).map(|(data, _)| data)
    }

    pub fn add_log(&mut self, location: Location, is_temp: bool) {
        let log = ChangeLog { location, is_temp };
        self.change_log.push(log)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ChangeLog {
    location: Location,
    is_temp: bool,
}

#[derive(Clone, Serialize, Deserialize)]
struct TempCollectedOutput {
    temp_output: HashMap<OutputKey, (ProcedureIo, bool)>,
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

pub struct Products<T> {
    pub secret: Vec<u8>,
    pub output: T,
}

// ==========================
//  Traits for the `Procedure` derive-macro
// ==========================

pub trait ProcessData {
    type Input;
    type Output;
    fn process(self, input: Self::Input) -> Result<Self::Output, engine::Error>;
}

pub trait GenerateSecret {
    type Input;
    type Output;
    fn generate(self, input: Self::Input) -> Result<Products<Self::Output>, engine::Error>;
}

pub trait DeriveSecret {
    type Input;
    type Output;
    fn derive(self, input: Self::Input, guard: GuardedVec<u8>) -> Result<Products<Self::Output>, engine::Error>;
}

pub trait UseSecret {
    type Input;
    type Output;
    fn use_secret(self, input: Self::Input, guard: GuardedVec<u8>) -> Result<Self::Output, engine::Error>;
}

// ==========================
//  Input /  Output Info
// ==========================

#[derive(Clone, Serialize, Deserialize)]
pub enum InputData<T> {
    Key(OutputKey),
    Value(T),
}

pub trait IntoInput<T> {
    fn into_input(self) -> InputData<T>;
}

impl<T> IntoInput<T> for T
where
    T: TryFromProcedureIo,
{
    fn into_input(self) -> InputData<T> {
        InputData::Value(self)
    }
}

impl<T> IntoInput<T> for OutputKey {
    fn into_input(self) -> InputData<T> {
        InputData::Key(self)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TempProduct<T> {
    pub write_to: T,
    pub is_temp: bool,
}

pub type TempTarget = TempProduct<Target>;
pub type TempOutput = TempProduct<OutputKey>;

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

pub trait TargetInfo {
    fn target(&self) -> Location {
        self.target_info().write_to.location.clone()
    }

    fn write_secret(mut self, location: Location, hint: RecordHint) -> Self
    where
        Self: Sized,
    {
        let target = self.target_info_mut();
        target.write_to = Target { location, hint };
        target.is_temp = false;
        self
    }

    fn target_info(&self) -> &TempTarget;
    fn target_info_mut(&mut self) -> &mut TempTarget;
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

impl TargetInfo for TempTarget {
    fn target_info(&self) -> &TempTarget {
        self
    }
    fn target_info_mut(&mut self) -> &mut TempTarget {
        self
    }
}

pub trait InputInfo {
    type Input;

    fn input_info(&self) -> &InputData<Self::Input>;
    fn input_info_mut(&mut self) -> &mut InputData<Self::Input>;
}

impl<T> InputInfo for InputData<T> {
    type Input = T;
    fn input_info(&self) -> &InputData<Self::Input> {
        self
    }

    fn input_info_mut(&mut self) -> &mut InputData<Self::Input> {
        self
    }
}

pub trait OutputInfo {
    fn output_key(&self) -> OutputKey {
        let o = self.output_info();
        o.write_to.clone()
    }

    fn store_output(mut self, key: OutputKey) -> Self
    where
        Self: Sized,
    {
        let info = self.output_info_mut();
        info.write_to = key;
        info.is_temp = false;
        self
    }

    fn output_info(&self) -> &TempOutput;
    fn output_info_mut(&mut self) -> &mut TempOutput;
}

impl OutputInfo for TempOutput {
    fn output_info(&self) -> &TempOutput {
        self
    }
    fn output_info_mut(&mut self) -> &mut TempOutput {
        self
    }
}

pub trait IntoProcedureIo {
    fn into_procedure_io(self) -> ProcedureIo;
}

impl IntoProcedureIo for Vec<u8> {
    fn into_procedure_io(self) -> ProcedureIo {
        ProcedureIo(self)
    }
}

impl IntoProcedureIo for String {
    fn into_procedure_io(self) -> ProcedureIo {
        let vec = self.into_bytes();
        vec.into_procedure_io()
    }
}
impl<const N: usize> IntoProcedureIo for [u8; N] {
    fn into_procedure_io(self) -> ProcedureIo {
        let vec: Vec<u8> = self.into();
        vec.into_procedure_io()
    }
}

impl<N: ArrayLength<u8>> IntoProcedureIo for GenericArray<u8, N> {
    fn into_procedure_io(self) -> ProcedureIo {
        let vec: Vec<u8> = self.into_iter().collect();
        vec.into_procedure_io()
    }
}

pub trait TryFromProcedureIo: Sized {
    type Error;
    fn try_from_procedure_io(value: ProcedureIo) -> Result<Self, Self::Error>;
}

impl TryFromProcedureIo for Vec<u8> {
    type Error = Infallible;
    fn try_from_procedure_io(value: ProcedureIo) -> Result<Self, Self::Error> {
        Ok(value.0)
    }
}

impl TryFromProcedureIo for String {
    type Error = FromUtf8Error;
    fn try_from_procedure_io(value: ProcedureIo) -> Result<Self, Self::Error> {
        String::from_utf8(value.0)
    }
}

impl<const N: usize> TryFromProcedureIo for [u8; N] {
    type Error = <[u8; N] as TryFrom<Vec<u8>>>::Error;

    fn try_from_procedure_io(value: ProcedureIo) -> Result<Self, Self::Error> {
        value.0.try_into()
    }
}

impl<N: ArrayLength<u8>> TryFromProcedureIo for GenericArray<u8, N> {
    type Error = crypto::Error;

    fn try_from_procedure_io(value: ProcedureIo) -> Result<Self, Self::Error> {
        let l = value.0.len();
        GenericArray::from_exact_iter(value.0.into_iter()).ok_or(crypto::Error::BufferSize {
            name: "Procedure I/O",
            needs: N::USIZE,
            has: l,
        })
    }
}

#[cfg(test)]
mod test {
    use hmac::digest::{consts::U113, generic_array::GenericArray};
    use stronghold_utils::test_utils::fresh;

    use super::{IntoProcedureIo, TryFromProcedureIo};
    use std::convert::TryInto;

    #[test]
    fn proc_io_vec() {
        let vec = fresh::bytestring();
        let proc_io = vec.clone().into_procedure_io();
        let converted = Vec::try_from_procedure_io(proc_io).unwrap();
        assert_eq!(vec.len(), converted.len());
        assert_eq!(vec, converted);
    }

    #[test]
    fn proc_io_string() {
        let string = fresh::string();
        let proc_io = string.clone().into_procedure_io();
        let converted = String::try_from_procedure_io(proc_io).unwrap();
        assert_eq!(string.len(), converted.len());
        assert_eq!(string, converted);
    }

    #[test]
    fn proc_io_array() {
        let array: [u8; 337] = vec![rand::random(); 337].try_into().unwrap();
        let proc_io = array.into_procedure_io();
        let converted = <[u8; 337]>::try_from_procedure_io(proc_io).unwrap();
        assert_eq!(array, converted);
    }

    #[test]
    fn proc_io_generic_array() {
        let vec: Vec<u8> = vec![rand::random(); 113];
        let gen_array = GenericArray::<u8, U113>::clone_from_slice(vec.as_slice());
        let proc_io = gen_array.into_procedure_io();
        let converted = GenericArray::<u8, U113>::try_from_procedure_io(proc_io).unwrap();
        assert_eq!(gen_array, converted);
    }
}
