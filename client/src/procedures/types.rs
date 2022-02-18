// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::primitives::PrimitiveProcedure;
use crate::{
    actors::{RecordError, VaultError},
    FatalEngineError, Location,
};
use actix::Message;
use engine::{
    runtime::GuardedVec,
    vault::{RecordHint, VaultId},
};
use serde::{Deserialize, Serialize};
use std::{
    convert::{TryFrom, TryInto},
    fmt::Debug,
    ops::Deref,
    string::FromUtf8Error,
};
use stronghold_utils::GuardDebug;
use thiserror::Error as DeriveError;

// ==========================
// Types
// ==========================

/// Complex Procedure that for executing one or multiple [`PrimitiveProcedure`]s.
///
/// Example:
/// // ```
/// # use iota_stronghold::{
/// #    procedures::*,
/// #    Location, RecordHint, Stronghold
/// # };
/// # use std::error::Error;
/// #
/// # async fn test() -> Result<(), Box<dyn Error>> {
/// #
/// let sh = Stronghold::init_stronghold_system("my-client".into(), vec![]).await?;
///
/// // Create a new seed, that only temporary exists during execution time
/// let generate = Slip10Generate::default();
///
/// let chain = Chain::from_u32(vec![0]);
/// // Use the newly created seed as input
/// let derive = Slip10Derive::new_from_seed(generate.target(), chain);
///
/// // Identifier / Key for a procedure's output
/// let k = OutputKey::new("chain-code");
///
/// // Target vault + record, in which the derived key will be written
/// let private_key = Location::generic("my-vault", "child-key");
///
/// let hint = RecordHint::new("private-key").unwrap();
/// let derive = derive
///     .store_output(k) // Configure that the output should be returned after execution
///     .write_secret(private_key, hint); // Set the record to be permanent in the vault
///
/// // Execute the procedures
/// let output = sh.runtime_exec(generate.then(derive)).await??;
///
/// // Get the desired output
/// let chain_code: ChainCode = output.single_output().unwrap();
/// #
/// # Ok(())
/// # }
/// // ```
#[derive(Clone, GuardDebug, Serialize, Deserialize)]
pub struct Procedure {
    inner: Vec<PrimitiveProcedure>,
}

impl ProcedureStep for Procedure {
    type Output = Vec<ProcedureIo>;

    fn execute<R: Runner>(self, runner: &mut R) -> Result<Self::Output, ProcedureError> {
        let mut out = Vec::new();
        let mut log = Vec::new();
        // Execute the primitive procedures sequentially.
        for proc in self.inner {
            if let Some(output) = proc.output() {
                log.push(output);
            }
            let output = match proc.execute(runner) {
                Ok(o) => o,
                Err(e) => {
                    for location in log {
                        let _ = runner.revoke_data(&location);
                    }
                    return Err(e);
                }
            };
            out.push(output);
        }
        Ok(out)
    }
}

impl Message for Procedure {
    type Result = Result<Vec<ProcedureIo>, ProcedureError>;
}

impl<P> From<P> for Procedure
where
    P: Into<PrimitiveProcedure>,
{
    fn from(p: P) -> Self {
        Self { inner: vec![p.into()] }
    }
}

/// Output of a primitive procedure, that is stored in the [`CollectedOutput`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

impl<T> From<VaultError<T>> for ProcedureError
where
    T: Into<FatalProcedureError> + Debug,
{
    fn from(e: VaultError<T>) -> Self {
        match e {
            VaultError::Procedure(e) => ProcedureError::Procedure(e.into()),
            other => ProcedureError::Engine(other.to_string().into()),
        }
    }
}

impl From<RecordError> for ProcedureError {
    fn from(e: RecordError) -> Self {
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

impl From<String> for FatalProcedureError {
    fn from(e: String) -> Self {
        FatalProcedureError(e)
    }
}

/// State that is passed to the each procedure on execution.
#[derive(Debug, Clone)]
pub struct State {
    /// Collected output from each primitive procedure in the chain.
    aggregated: Vec<ProcedureIo>,
    /// Log of newly created records in the vault.
    change_log: Vec<Location>,
}

impl State {
    /// Add a procedure output to the collected output.
    pub fn insert_output(&mut self, value: ProcedureIo) {
        self.aggregated.push(value)
    }

    /// Get the output from a previously executed procedure.
    pub fn get_output(&self, index: usize) -> Option<&ProcedureIo> {
        self.aggregated.get(index)
    }

    /// Log a newly created record.
    pub fn add_log(&mut self, location: Location) {
        self.change_log.push(location)
    }
}
// ==========================
// Traits
// ==========================

/// Central trait that implements a procedure's logic.
pub trait ProcedureStep {
    type Output;
    /// Execute the procedure on a runner.
    /// The state collects the output from each procedure and writes a log of newly created records.
    fn execute<R: Runner>(self, runner: &mut R) -> Result<Self::Output, ProcedureError>;

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

    fn write_to_vault(&mut self, location1: &Location, hint: RecordHint, value: Vec<u8>) -> Result<(), RecordError>;

    fn revoke_data(&mut self, location: &Location) -> Result<(), RecordError>;

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
pub trait ProcessData: Sized {
    // Non-secret output type.
    type Output: Into<ProcedureIo>;

    fn process(self) -> Result<Self::Output, FatalProcedureError>;

    fn execute<R: Runner>(self, _runner: &mut R) -> Result<Self::Output, ProcedureError> {
        let output = self.process()?;
        Ok(output)
    }
}

/// No secret is used, a new secret is created.
pub trait GenerateSecret: Sized {
    // Non-secret output type.
    type Output: Into<ProcedureIo>;

    fn generate(self) -> Result<Products<Self::Output>, FatalProcedureError>;

    fn target(&self) -> (&Location, RecordHint);

    fn execute<R: Runner>(self, runner: &mut R) -> Result<Self::Output, ProcedureError> {
        let (target, hint) = self.target();
        let target = target.clone();
        let Products { output, secret } = self.generate()?;
        runner.write_to_vault(&target, hint, secret)?;
        Ok(output)
    }
}

/// Existing secret is used, a new secret is created.
pub trait DeriveSecret: Sized {
    // Non-secret output type.
    type Output: Into<ProcedureIo>;

    fn derive(self, guard: GuardedVec<u8>) -> Result<Products<Self::Output>, FatalProcedureError>;

    fn source(&self) -> &Location;

    fn target(&self) -> (&Location, RecordHint);

    fn execute<R: Runner>(self, runner: &mut R) -> Result<Self::Output, ProcedureError> {
        let source = self.source().clone();
        let (target, hint) = self.target();
        let target = target.clone();
        let f = |guard| self.derive(guard);
        let output = runner.exec_proc(&source, &target, hint, f)?;
        Ok(output)
    }
}

/// Existing secret is used, no new secret is created.
pub trait UseSecret: Sized {
    // Non-secret output type.
    type Output: Into<ProcedureIo>;

    fn use_secret(self, guard: GuardedVec<u8>) -> Result<Self::Output, FatalProcedureError>;

    fn source(&self) -> &Location;

    fn execute<R: Runner>(self, runner: &mut R) -> Result<Self::Output, ProcedureError> {
        let source = self.source().clone();
        let f = |guard| self.use_secret(guard);
        let output = runner.get_guard(&source, f)?;
        Ok(output)
    }
}

// ==========================
//  Input /  Output Info
// ==========================

impl From<()> for ProcedureIo {
    fn from(_: ()) -> Self {
        ProcedureIo(Vec::new())
    }
}

impl From<Vec<u8>> for ProcedureIo {
    fn from(v: Vec<u8>) -> Self {
        ProcedureIo(v)
    }
}

impl From<String> for ProcedureIo {
    fn from(s: String) -> Self {
        s.into_bytes().into()
    }
}

impl<const N: usize> From<[u8; N]> for ProcedureIo {
    fn from(a: [u8; N]) -> Self {
        a.to_vec().into()
    }
}

impl From<ProcedureIo> for () {
    fn from(_: ProcedureIo) -> Self {}
}

impl From<ProcedureIo> for Vec<u8> {
    fn from(value: ProcedureIo) -> Self {
        value.0
    }
}

impl TryFrom<ProcedureIo> for String {
    type Error = FromUtf8Error;
    fn try_from(value: ProcedureIo) -> Result<Self, Self::Error> {
        String::from_utf8(value.0)
    }
}

impl<const N: usize> TryFrom<ProcedureIo> for [u8; N] {
    type Error = <[u8; N] as TryFrom<Vec<u8>>>::Error;

    fn try_from(value: ProcedureIo) -> Result<Self, Self::Error> {
        value.0.try_into()
    }
}

#[cfg(test)]
mod test {
    use super::ProcedureIo;
    use std::convert::{TryFrom, TryInto};
    use stronghold_utils::random;

    #[test]
    fn proc_io_vec() {
        let vec = random::bytestring(2048);
        let proc_io: ProcedureIo = vec.clone().into();
        let converted = Vec::try_from(proc_io).unwrap();
        assert_eq!(vec.len(), converted.len());
        assert_eq!(vec, converted);
    }

    #[test]
    fn proc_io_string() {
        let string = random::string(2048);
        let proc_io: ProcedureIo = string.clone().into();
        let converted = String::try_from(proc_io).unwrap();
        assert_eq!(string.len(), converted.len());
        assert_eq!(string, converted);
    }

    #[test]
    fn proc_io_array() {
        let mut test_vec = Vec::with_capacity(337);
        for _ in 0..test_vec.capacity() {
            test_vec.push(random::random())
        }
        let array: [u8; 337] = test_vec.try_into().unwrap();
        let proc_io: ProcedureIo = array.into();
        let converted = <[u8; 337]>::try_from(proc_io).unwrap();
        assert_eq!(array, converted);
    }
}
