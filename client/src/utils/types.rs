// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use serde::{de, ser, Deserialize, Serialize};
use zeroize::Zeroize;

/// A type alias for the empty `ResultMessage<()>` type.
pub type StatusMessage = ResultMessage<()>;

/// Return value used for Actor Messages.  Can specify an Error or an Ok result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultMessage<T> {
    Ok(T),
    Error(String),
}

impl ResultMessage<()> {
    pub const OK: Self = ResultMessage::Ok(());
}

/// A `Location` type used to specify where in the `Stronghold` a piece of data should be stored. A generic location
/// specifies a non-versioned location while a counter location specifies a versioned location. The Counter location can
/// be used to get the head of the version chain by passing in `None` as the counter index. Otherwise, counter records
/// are referenced through their associated index.  On Read, the `None` location is the latest record in the version
/// chain while on Write, the `None` location is the next record in the version chain.
#[derive(Debug, Clone)]
pub enum Location {
    Generic {
        vault_path: Vec<u8>,
        record_path: Vec<u8>,
    },
    Counter {
        vault_path: Vec<u8>,
        counter: Option<usize>,
    },
}

impl Location {
    /// Gets the vault_path from the Location.
    pub fn vault_path(&self) -> &[u8] {
        match self {
            Self::Generic { vault_path, .. } => vault_path,
            Self::Counter { vault_path, .. } => vault_path,
        }
    }

    /// Creates a generic location from types that implement `Into<Vec<u8>>`.
    pub fn generic<V: Into<Vec<u8>>, R: Into<Vec<u8>>>(vault_path: V, record_path: R) -> Self {
        Self::Generic {
            vault_path: vault_path.into(),
            record_path: record_path.into(),
        }
    }

    /// Creates a counter location from a type that implements `Into<Vec<u8>>` and a counter type that implements
    /// `Into<usize>`
    pub fn counter<V: Into<Vec<u8>>, C: Into<usize>>(vault_path: V, counter: Option<C>) -> Self {
        Self::Counter {
            vault_path: vault_path.into(),
            counter: counter.map(|c| c.into()),
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
    pub const fn const_counter(vault_path: Vec<u8>, counter: Option<usize>) -> Self {
        Self::Counter { vault_path, counter }
    }
}

impl AsRef<Location> for Location {
    fn as_ref(&self) -> &Location {
        self
    }
}

/// Policy options for modifying an entire Stronghold.  Must be specified on creation.
pub enum StrongholdFlags {
    IsReadable(bool),
}

/// Policy options for for a specific vault.  Must be specified on creation.
pub enum VaultFlags {}

pub trait ReadSecret<S>
where
    S: Zeroize,
{
    fn read_secret(&self) -> &S;
}

pub trait CloneSecret: Clone + Zeroize {}

pub trait SerializeSecret: Serialize {}

pub struct Secret<S>
where
    S: Zeroize,
{
    value: S,
}

impl<S> Secret<S>
where
    S: Zeroize,
{
    pub fn new(value: S) -> Self {
        Self { value }
    }
}

impl<S> ReadSecret<S> for Secret<S>
where
    S: Zeroize,
{
    fn read_secret(&self) -> &S {
        &self.value
    }
}

impl<S> From<S> for Secret<S>
where
    S: Zeroize,
{
    fn from(value: S) -> Self {
        Self::new(value)
    }
}

impl<S> Clone for Secret<S>
where
    S: CloneSecret,
{
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
        }
    }
}

impl<S> Drop for Secret<S>
where
    S: Zeroize,
{
    fn drop(&mut self) {
        self.value.zeroize()
    }
}

impl<'de, T> Deserialize<'de> for Secret<T>
where
    T: Zeroize + Clone + de::DeserializeOwned + Sized,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Secret::new)
    }
}

impl<T> Serialize for Secret<T>
where
    T: Zeroize + SerializeSecret + Serialize + Sized,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        self.read_secret().serialize(serializer)
    }
}
