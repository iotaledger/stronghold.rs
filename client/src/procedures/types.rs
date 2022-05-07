// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{FatalEngineError, Location, Provider, RecordError, VaultError};
use engine::{
    runtime::memories::buffer::Buffer,
    vault::{BoxProvider, VaultId},
};
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, string::FromUtf8Error};
use thiserror::Error as DeriveError;

/// Bridge to the engine that is required for using / writing / revoking secrets in the vault.
pub trait Runner {
    /// Applies `f` to the buffers from the given `locations`.
    fn get_guards<F, T, const N: usize>(
        &self,
        locations: [Location; N],
        f: F,
    ) -> Result<T, VaultError<FatalProcedureError>>
    where
        F: FnOnce([Buffer<u8>; N]) -> Result<T, FatalProcedureError>;

    // Execute a function that uses the secret stored at `source_locations`. From the returned `Products` the secret is
    // written into `target_location` and the output is returned.
    fn exec_proc<F, T, const N: usize>(
        &self,
        source_locations: [Location; N],
        target_location: &Location,
        f: F,
    ) -> Result<T, VaultError<FatalProcedureError>>
    where
        F: FnOnce([Buffer<u8>; N]) -> Result<Products<T>, FatalProcedureError>;

    fn write_to_vault(&self, location1: &Location, value: Vec<u8>) -> Result<(), RecordError>;

    fn revoke_data(&self, location: &Location) -> Result<(), RecordError>;

    fn garbage_collect(&self, vault_id: VaultId) -> bool;
}

/// Products of a procedure.
pub struct Products<T> {
    /// New secret.
    pub secret: Vec<u8>,
    /// Non-secret Output.
    pub output: T,
}

/// Procedure to create, use or remove secrets from a stronghold vault.
/// The `primitives::procedure` macro may be used to auto-implement this
/// trait for procedures that implement `GenerateSecret`, `DeriveSecret` or `UseSecret`.
pub trait Procedure: Sized {
    // Non-secret output type.
    type Output: TryFrom<ProcedureOutput>;

    // made immutable
    fn execute<R: Runner>(self, _runner: &R) -> Result<Self::Output, ProcedureError>;
}

/// Trait for procedures that generate a new secret.
pub trait GenerateSecret: Sized {
    type Output;

    fn generate(self) -> Result<Products<Self::Output>, FatalProcedureError>;

    fn target(&self) -> &Location;

    fn exec<R: Runner>(self, runner: &R) -> Result<Self::Output, ProcedureError> {
        let target = self.target();
        let target = target.clone();
        let Products { output, secret } = self.generate()?;
        runner.write_to_vault(&target, secret)?;
        Ok(output)
    }
}

/// Trait for procedures that use an existing secret to derive a new one.
pub trait DeriveSecret<const N: usize>: Sized {
    type Output;

    fn derive(self, guard: [Buffer<u8>; N]) -> Result<Products<Self::Output>, FatalProcedureError>;

    fn source(&self) -> [Location; N];

    fn target(&self) -> &Location;

    fn exec<R: Runner>(self, runner: &R) -> Result<Self::Output, ProcedureError> {
        let sources: [Location; N] = self.source();
        let target = self.target();
        let target = target.clone();
        let f = |guard| self.derive(guard);
        let output = runner.exec_proc(sources, &target, f)?;
        Ok(output)
    }
}

/// Trait for procedures that use an existing secret.
pub trait UseSecret<const N: usize>: Sized {
    type Output;

    fn use_secret(self, guard: [Buffer<u8>; N]) -> Result<Self::Output, FatalProcedureError>;

    fn source(&self) -> [Location; N];

    fn exec<R: Runner>(self, runner: &R) -> Result<Self::Output, ProcedureError> {
        let source: [Location; N] = self.source();
        let f = |guard| self.use_secret(guard);
        let output = runner.get_guards(source, f)?;
        Ok(output)
    }
}

/// Output of a [`StrongholdProcedure`][super::StrongholdProcedure].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcedureOutput(Vec<u8>);

impl From<()> for ProcedureOutput {
    fn from(_: ()) -> Self {
        ProcedureOutput(Vec::new())
    }
}

impl From<Vec<u8>> for ProcedureOutput {
    fn from(v: Vec<u8>) -> Self {
        ProcedureOutput(v)
    }
}

impl From<String> for ProcedureOutput {
    fn from(s: String) -> Self {
        s.into_bytes().into()
    }
}

impl<const N: usize> From<[u8; N]> for ProcedureOutput {
    fn from(a: [u8; N]) -> Self {
        a.to_vec().into()
    }
}

impl From<ProcedureOutput> for () {
    fn from(_: ProcedureOutput) -> Self {}
}

impl From<ProcedureOutput> for Vec<u8> {
    fn from(value: ProcedureOutput) -> Self {
        value.0
    }
}

impl TryFrom<ProcedureOutput> for String {
    type Error = FromUtf8Error;
    fn try_from(value: ProcedureOutput) -> Result<Self, Self::Error> {
        String::from_utf8(value.0)
    }
}

impl<const N: usize> TryFrom<ProcedureOutput> for [u8; N] {
    type Error = <[u8; N] as TryFrom<Vec<u8>>>::Error;

    fn try_from(value: ProcedureOutput) -> Result<Self, Self::Error> {
        value.0.try_into()
    }
}

/// Error on procedure execution.
#[derive(DeriveError, Debug, Clone, Serialize, Deserialize)]
pub enum ProcedureError {
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

#[cfg(test)]
mod test {
    use super::ProcedureOutput;
    use stronghold_utils::random;

    #[test]
    fn proc_io_vec() {
        let vec = random::bytestring(2048);
        let proc_io: ProcedureOutput = vec.clone().into();
        let converted = Vec::try_from(proc_io).unwrap();
        assert_eq!(vec.len(), converted.len());
        assert_eq!(vec, converted);
    }

    #[test]
    fn proc_io_string() {
        let string = random::string(2048);
        let proc_io: ProcedureOutput = string.clone().into();
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
        let proc_io: ProcedureOutput = array.into();
        let converted = <[u8; 337]>::try_from(proc_io).unwrap();
        assert_eq!(array, converted);
    }
}
