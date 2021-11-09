// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::primitives::PrimitiveProcedure;
use crate::{actors::VaultError, state::secure::SecureClient, FatalEngineError, Location};
use actix::Message;
use engine::{
    runtime::GuardedVec,
    vault::{RecordHint, VaultId},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    convert::{Infallible, TryFrom, TryInto},
    ops::Deref,
    string::FromUtf8Error,
};
use stronghold_utils::{random, GuardDebug};
use thiserror::Error as DeriveError;

// ==========================
// Types
// ==========================

/// Complex Procedure that chains multiple primitive procedures.
#[derive(Clone, GuardDebug, Serialize, Deserialize)]
pub struct Procedure {
    inner: Vec<PrimitiveProcedure>,
}

impl Procedure {
    /// Execute the procedure on a runner, e.g. the `SecureClient`
    pub fn run<R: Runner>(self, runner: &mut R) -> Result<CollectedOutput, ProcedureError> {
        // State that is passed to each procedure for writing their output into it.
        let mut state = State {
            aggregated: TempCollectedOutput {
                temp_output: HashMap::default(),
            },
            change_log: Vec::default(),
        };
        // Execute procedures.
        match self.execute(runner, &mut state) {
            Ok(()) => {
                // Delete temporary records.
                Self::revoke_records(runner, state.change_log, true);
                // Convert TempCollectedOutput into CollectedOutput by filtering temporary outputs.
                Ok(state.aggregated.into())
            }
            Err(e) => {
                // Rollback written data.
                Self::revoke_records(runner, state.change_log, false);
                Err(e)
            }
        }
    }

    // Revoke all / temporary records from vault, and garbage collect.
    fn revoke_records<R: Runner>(runner: &mut R, logs: Vec<ChangeLog>, remove_only_temp: bool) {
        let mut vaults = HashSet::new();
        for entry in logs {
            if entry.is_temp || !remove_only_temp {
                let (v, _) = SecureClient::resolve_location(&entry.location);
                let _ = runner.revoke_data(&entry.location);
                if !vaults.contains(&v) {
                    vaults.insert(v);
                }
            }
        }
        for vault_id in vaults {
            let _ = runner.garbage_collect(vault_id);
        }
    }
}

impl ProcedureStep for Procedure {
    fn execute<R: Runner>(self, runner: &mut R, state: &mut State) -> Result<(), ProcedureError> {
        // Execute the primitive procedures sequentially.
        self.inner.into_iter().try_for_each(|p| p.execute(runner, state))
    }
}

impl Message for Procedure {
    type Result = Result<CollectedOutput, ProcedureError>;
}

impl<P> From<P> for Procedure
where
    P: Into<PrimitiveProcedure>,
{
    fn from(p: P) -> Self {
        Self { inner: vec![p.into()] }
    }
}

/// Collected permanent non-secret output of procedures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectedOutput {
    output: HashMap<OutputKey, ProcedureIo>,
}

impl CollectedOutput {
    /// Take the output associated with the key from the output, convert it to the required type and return it.
    ///
    /// If the output can not be converted into `T`, it is inserted back and `None` is returned.
    /// Conversion into `T = Vec<u8>` will never fail.
    pub fn take<T>(&mut self, key: &OutputKey) -> Option<T>
    where
        T: TryFromProcedureIo,
    {
        let value = self.output.remove(key)?;
        match T::try_from_procedure_io(value.clone()) {
            Ok(v) => Some(v),
            Err(_) => {
                self.output.insert(key.clone(), value);
                None
            }
        }
    }

    /// Consume the `CollectedOutput`, take the next value found and convert it to `T`.
    /// Return `None` if it is empty, or the value could not be converted to `T`.
    /// Conversion into `T = Vec<u8>` will never fail.
    pub fn single_output<T>(self) -> Option<T>
    where
        T: TryFromProcedureIo,
    {
        self.into_iter()
            .next()
            .and_then(|(_, v)| T::try_from_procedure_io(v).ok())
    }
}

/// Returns an iterator over all (OutputKey, ProcedureIo) pairs in the collected output.
impl IntoIterator for CollectedOutput {
    type IntoIter = <HashMap<OutputKey, ProcedureIo> as IntoIterator>::IntoIter;
    type Item = <HashMap<OutputKey, ProcedureIo> as IntoIterator>::Item;
    fn into_iter(self) -> Self::IntoIter {
        self.output.into_iter()
    }
}

/// Convert from `TempCollectedOutput` by removing all temporary records.
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

/// Identifier for output in the `CollectedOutput`.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OutputKey(String);

impl OutputKey {
    pub fn new<K: ToString>(key: K) -> Self {
        OutputKey(key.to_string())
    }

    pub fn random() -> Self {
        OutputKey(rand::random::<char>().into())
    }
}

/// Output of a primitive procedure, that is stored in the [`CollectedOutput`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcedureIo(Vec<u8>);

impl Deref for ProcedureIo {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Error on procedure execution.
#[derive(DeriveError, Debug, Clone, Serialize, Deserialize)]
pub enum ProcedureError {
    /// The input fetched from the collected output can not be converted to the required type.
    #[error("Invalid Input Type")]
    InvalidInput,

    /// No input for the specified key in the collected output.
    #[error("Missing Input")]
    MissingInput,

    /// Operation on the vault failed.
    #[error("engine: {0}")]
    Engine(#[from] FatalEngineError),

    /// Operation on the vault failed.
    #[error("procedure: {0}")]
    Procedure(#[from] FatalProcedureError),
}

impl From<VaultError<FatalProcedureError>> for ProcedureError {
    fn from(e: VaultError<FatalProcedureError>) -> Self {
        match e {
            VaultError::Procedure(e) => ProcedureError::Procedure(e),
            other => ProcedureError::Engine(other.to_string().into()),
        }
    }
}

impl From<VaultError> for ProcedureError {
    fn from(e: VaultError) -> Self {
        ProcedureError::Engine(e.into())
    }
}

/// Execution of the procedure failed.
#[derive(DeriveError, Debug, Clone, Serialize, Deserialize)]
#[error("fatal procedure error {0}")]
pub struct FatalProcedureError(String);

impl From<crypto::Error> for FatalProcedureError {
    fn from(e: crypto::Error) -> Self {
        FatalProcedureError(e.to_string())
    }
}

/// State that is passed to the each procedure on execution.
#[derive(Debug, Clone)]
pub struct State {
    /// Collected output from each primitive procedure in the chain.
    aggregated: TempCollectedOutput,
    /// Log of newly created records in the vault.
    change_log: Vec<ChangeLog>,
}

impl State {
    /// Add a procedure output to the collected output.
    pub fn insert_output(&mut self, key: OutputKey, value: ProcedureIo, is_temp: bool) {
        self.aggregated.temp_output.insert(key, (value, is_temp));
    }

    /// Get the output from a previously executed procedure.
    pub fn get_output(&self, key: &OutputKey) -> Option<&ProcedureIo> {
        self.aggregated.temp_output.get(key).map(|(data, _)| data)
    }

    /// Log a newly created record.
    /// If `is_temp` is true, the record will be removed after the execution of all procedures in the chain finished.
    pub fn add_log(&mut self, location: Location, is_temp: bool) {
        let log = ChangeLog { location, is_temp };
        self.change_log.push(log)
    }
}

/// Log a newly created record.
#[derive(Debug, Clone)]
struct ChangeLog {
    location: Location,
    /// If `is_temp` is true, the record will be removed after the execution of all procedures in the chain finished.
    is_temp: bool,
}

#[derive(Debug, Clone)]
struct TempCollectedOutput {
    // Collected ProcedureIo during execution, and whether it is temporary or not.
    temp_output: HashMap<OutputKey, (ProcedureIo, bool)>,
}

// ==========================
// Traits
// ==========================

/// Central trait that implements a procedures logic.
pub trait ProcedureStep {
    /// Execute the procedure on a runner.
    /// The state collects the output from each procedure and writes a log of newly created records.
    fn execute<R: Runner>(self, runner: &mut R, state: &mut State) -> Result<(), ProcedureError>;

    /// Chain a next procedure to the current one.
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

/// Bridge to the engine that is required for using / writing / revoking secrets in the vault.
pub trait Runner {
    fn get_guard<F, T>(&mut self, location0: &Location, f: F) -> Result<T, VaultError<FatalProcedureError>>
    where
        F: FnOnce(GuardedVec<u8>) -> Result<T, FatalProcedureError>;

    fn exec_proc<F, T>(
        &mut self,
        location0: &Location,
        location1: &Location,
        hint: RecordHint,
        f: F,
    ) -> Result<T, VaultError<FatalProcedureError>>
    where
        F: FnOnce(GuardedVec<u8>) -> Result<Products<T>, FatalProcedureError>;

    fn write_to_vault(&mut self, location1: &Location, hint: RecordHint, value: Vec<u8>) -> Result<(), VaultError>;

    fn revoke_data(&mut self, location: &Location) -> Result<(), VaultError>;

    fn garbage_collect(&mut self, vault_id: VaultId) -> bool;
}

/// Products of a procedure.
pub struct Products<T> {
    /// New secret.
    pub secret: Vec<u8>,
    /// Non-secret Output.
    pub output: T,
}

// ==========================
//  Traits for the `Procedure` derive-macro
// ==========================

/// No secret is used, no new secret is created.
pub trait ProcessData {
    // Non-secret input type.
    type Input;
    // Non-secret output type.
    type Output;
    fn process(self, input: Self::Input) -> Result<Self::Output, FatalProcedureError>;
}

/// No secret is used, a new secret is created.
pub trait GenerateSecret {
    // Non-secret input type.
    type Input;
    // Non-secret output type.
    type Output;
    fn generate(self, input: Self::Input) -> Result<Products<Self::Output>, FatalProcedureError>;
}

/// Existing secret is used, a new secret is created.
pub trait DeriveSecret {
    // Non-secret input type.
    type Input;
    // Non-secret output type.
    type Output;
    fn derive(self, input: Self::Input, guard: GuardedVec<u8>) -> Result<Products<Self::Output>, FatalProcedureError>;
}

/// Existing secret is used, no new secret is created.
pub trait UseSecret {
    // Non-secret input type.
    type Input;
    // Non-secret output type.
    type Output;
    fn use_secret(self, input: Self::Input, guard: GuardedVec<u8>) -> Result<Self::Output, FatalProcedureError>;
}

// ==========================
//  Input /  Output Info
// ==========================

/// Non-secret input for a procedure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InputData<T> {
    /// Take input dynamically from the `CollectedOutput`,
    /// i.g. use the output of a previously executed procedure as input.
    Key(OutputKey),
    /// Fixed input.
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

/// Location of a Secret / Non-secret Product of a primitive procedure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TempProduct<T> {
    /// Location / Key into which the output is written.
    ///
    /// In case of a secret, this is a `Target {Location, RecordHing`,
    /// in case of a non-secret output, this is a `OutputKey`.
    pub write_to: T,
    /// Whether the product is revoked/ dropped after the execution finished.
    pub is_temp: bool,
}

/// New Secret.
pub type TempTarget = TempProduct<Target>;
/// Non-Secret Output.
pub type TempOutput = TempProduct<OutputKey>;

/// Location of an existing secret.
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

/// Location into which a new secret should be written.
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub location: Location,
    pub hint: RecordHint,
}

impl Target {
    pub fn random() -> Self {
        let location = Location::generic("TEMP".as_bytes(), random::bytestring(32));
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

/// Non-secret input for a procedure.
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

/// Specify where non-secret output should be written to.
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

#[cfg(test)]
mod test {
    use stronghold_utils::random;

    use super::{IntoProcedureIo, TryFromProcedureIo};
    use std::convert::TryInto;

    #[test]
    fn proc_io_vec() {
        let vec = random::bytestring(2048);
        let proc_io = vec.clone().into_procedure_io();
        let converted = Vec::try_from_procedure_io(proc_io).unwrap();
        assert_eq!(vec.len(), converted.len());
        assert_eq!(vec, converted);
    }

    #[test]
    fn proc_io_string() {
        let string = random::string(2048);
        let proc_io = string.clone().into_procedure_io();
        let converted = String::try_from_procedure_io(proc_io).unwrap();
        assert_eq!(string.len(), converted.len());
        assert_eq!(string, converted);
    }

    #[test]
    fn proc_io_array() {
        let array: [u8; 337] = vec![random::random(); 337].try_into().unwrap();
        let proc_io = array.into_procedure_io();
        let converted = <[u8; 337]>::try_from_procedure_io(proc_io).unwrap();
        assert_eq!(array, converted);
    }
}
