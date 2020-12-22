// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use serde::{de, ser, Deserialize, Serialize};
use zeroize::Zeroize;

pub type StatusMessage = ResultMessage<()>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultMessage<T> {
    Ok(T),
    Error(String),
}

impl ResultMessage<()> {
    pub const OK: Self = ResultMessage::Ok(());
}

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
    pub fn vault_path(&self) -> &[u8] {
        match self {
            Self::Generic { vault_path, .. } => vault_path,
            Self::Counter { vault_path, .. } => vault_path,
        }
    }

    pub fn generic<V: Into<Vec<u8>>, R: Into<Vec<u8>>>(vault_path: V, record_path: R) -> Self {
        Self::Generic {
            vault_path: vault_path.into(),
            record_path: record_path.into(),
        }
    }

    pub fn counter<V: Into<Vec<u8>>, C: Into<usize>>(vault_path: V, counter: Option<C>) -> Self {
        Self::Counter {
            vault_path: vault_path.into(),
            counter: counter.map(|c| c.into()),
        }
    }

    pub const fn const_generic(vault_path: Vec<u8>, record_path: Vec<u8>) -> Self {
        Self::Generic {
            vault_path,
            record_path,
        }
    }

    pub const fn const_counter(vault_path: Vec<u8>, counter: Option<usize>) -> Self {
        Self::Counter { vault_path, counter }
    }
}

impl AsRef<Location> for Location {
    fn as_ref(&self) -> &Location {
        self
    }
}

pub enum StrongholdFlags {
    IsReadable(bool),
}

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
