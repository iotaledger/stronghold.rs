// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{any::Any, convert::TryInto};

use engine::vault::{RecordId, VaultId};
use serde::{Deserialize, Serialize};
use thiserror::Error as DeriveError;

use super::LoadFromPath;

/// A type alias for the empty `ResultMessage<()>` type.
pub type StatusMessage = ResultMessage<()>;

/// Return value used for Actor Messages.  Can specify an `Error` or an `Ok` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResultMessage<T> {
    Ok(T),
    Error(String),
}

impl ResultMessage<()> {
    pub const OK: Self = ResultMessage::Ok(());
}

impl<T> ResultMessage<T> {
    /// Returns true, if the [`ResultMessage`] contains an `Ok` value
    pub fn is_ok(&self) -> bool {
        matches!(self, ResultMessage::Ok(_))
    }

    /// Returns true, if the [`ResultMessage`] contains an `Error`
    pub fn is_err(&self) -> bool {
        !self.is_ok()
    }
}

impl<T> From<Result<T, String>> for ResultMessage<T> {
    fn from(result: Result<T, String>) -> Self {
        match result {
            Ok(t) => ResultMessage::Ok(t),
            Err(s) => ResultMessage::Error(s),
        }
    }
}

impl<T> From<Result<T, anyhow::Error>> for ResultMessage<T> {
    fn from(result: Result<T, anyhow::Error>) -> Self {
        match result {
            Ok(t) => ResultMessage::Ok(t),
            Err(e) => ResultMessage::Error(format!("{:?}", e)),
        }
    }
}

#[derive(DeriveError, Debug)]
pub enum LocationError {
    #[error("Cannot convert Location: ({0})")]
    ConversionError(String),
}

/// A `Location` type used to specify where in the `Stronghold` a piece of data should be stored. A generic location
/// specifies a non-versioned location while a counter location specifies a versioned location. The Counter location can
/// be used to get the head of the version chain by passing in `None` as the counter index. Otherwise, counter records
/// are referenced through their associated index.  On Read, the `None` location is the latest record in the version
/// chain while on Write, the `None` location is the next record in the version chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Location {
    Generic { vault_path: Vec<u8>, record_path: Vec<u8> },
    Counter { vault_path: Vec<u8>, counter: usize },
}

impl PartialEq for Location {
    fn eq(&self, other: &Self) -> bool {
        if self.type_id() != other.type_id() {
            return false;
        }

        match (&self, &other) {
            (
                &Self::Generic {
                    vault_path: vp0,
                    record_path: rp0,
                },
                &Self::Generic {
                    vault_path: vp1,
                    record_path: rp1,
                },
            ) => (vp0 == vp1) && (rp0 == rp1),
            (
                &Self::Counter {
                    vault_path: vp0,
                    counter: c0,
                },
                &Self::Counter {
                    vault_path: vp1,
                    counter: c1,
                },
            ) => (vp0 == vp1) && (c0 == c1),
            _ => false,
        }
    }
}

impl TryInto<VaultId> for &Location {
    type Error = LocationError;

    fn try_into(self) -> Result<VaultId, Self::Error> {
        VaultId::load_from_path(self.vault_path(), self.vault_path())
            .map_err(|error| LocationError::ConversionError(error.to_string()))
    }
}

impl TryInto<RecordId> for &Location {
    type Error = LocationError;

    fn try_into(self) -> Result<RecordId, Self::Error> {
        match self {
            Location::Generic {
                vault_path,
                record_path,
            } => {
                let vid = VaultId::load_from_path(vault_path, vault_path)
                    .map_err(|error| LocationError::ConversionError(error.to_string()))?;

                RecordId::load_from_path(vid.as_ref(), record_path)
                    .map_err(|error| LocationError::ConversionError(error.to_string()))
            }

            Location::Counter { vault_path, counter } => {
                let vault_path = vault_path;

                let path = match counter {
                    0 => format!("{:?}{}", vault_path, "first_record"),
                    _ => format!("{:?}{}", vault_path, counter),
                };

                RecordId::load_from_path(path.as_bytes(), path.as_bytes())
                    .map_err(|error| LocationError::ConversionError(error.to_string()))
            }
        }
    }
}

impl Location {
    /// Gets the vault_path from the Location.
    pub fn vault_path(&self) -> &[u8] {
        match self {
            Self::Generic { vault_path, .. } => vault_path,
            Self::Counter { vault_path, .. } => vault_path,
        }
    }

    /// Creates a generic location from types that implement [`Into<Vec<u8>>`].
    pub fn generic<V: Into<Vec<u8>>, R: Into<Vec<u8>>>(vault_path: V, record_path: R) -> Self {
        Self::Generic {
            vault_path: vault_path.into(),
            record_path: record_path.into(),
        }
    }

    /// Creates a counter location from a type that implements [`Into<Vec<u8>>`] and a counter type that implements
    /// [`Into<usize>`]
    pub fn counter<V: Into<Vec<u8>>, C: Into<usize>>(vault_path: V, counter: C) -> Self {
        Self::Counter {
            vault_path: vault_path.into(),
            counter: counter.into(),
        }
    }

    /// Used to generate a constant generic location.
    pub const fn const_generic(vault_path: Vec<u8>, record_path: Vec<u8>) -> Self {
        Self::Generic {
            vault_path,
            record_path,
        }
    }

    /// used to generate a constant counter location.
    pub const fn const_counter(vault_path: Vec<u8>, counter: usize) -> Self {
        Self::Counter { vault_path, counter }
    }
}

impl AsRef<Location> for Location {
    fn as_ref(&self) -> &Location {
        self
    }
}

/// Policy options for modifying an entire Stronghold.  Must be specified on creation.
///
/// note:
/// This is deprecated.
#[derive(Clone, Debug)]
pub enum StrongholdFlags {
    IsReadable(bool),
}

/// Policy options for for a specific vault.  Must be specified on creation.
#[derive(Clone, Debug)]
pub enum VaultFlags {}
