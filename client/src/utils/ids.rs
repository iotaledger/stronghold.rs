// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use crypto::macs::hmac::HMAC_SHA512;

use engine::vault::{Base64Encodable, BoxProvider, RecordId};

use std::{
    convert::{TryFrom, TryInto},
    fmt::{self, Debug, Formatter},
    hash::Hash,
};

use crate::line_error;

/// Client ID type used to identify a client.
#[repr(transparent)]
#[derive(Copy, Clone, Default, Hash, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClientId(ID);

/// Vault ID type used to identify a vault.
#[repr(transparent)]
#[derive(Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub struct VaultId(ID);

/// A generic ID type used as the underlying type for the `ClientId` and `VaultId` types.
#[repr(transparent)]
#[derive(Copy, Clone, Hash, Default, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
struct ID([u8; 24]);

impl AsRef<[u8]> for ID {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub trait LoadFromPath: Sized {
    /// Load from some data and a path.
    fn load_from_path(data: &[u8], path: &[u8]) -> crate::Result<Self>;
}

impl LoadFromPath for RecordId {
    fn load_from_path(data: &[u8], path: &[u8]) -> crate::Result<Self> {
        let mut buf = [0; 64];
        HMAC_SHA512(data, path, &mut buf);

        let (id, _) = buf.split_at(24);

        Ok(id.try_into().expect(line_error!()))
    }
}

impl Debug for ID {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Chain({})", self.0.base64())
    }
}

impl ID {
    /// Create a new random `ID`.
    pub fn random<P: BoxProvider>() -> crate::Result<Self> {
        let mut buf = [0; 24];
        P::random_buf(&mut buf)?;

        Ok(Self(buf))
    }

    /// Load an `ID` from some data.
    pub fn load(data: &[u8]) -> crate::Result<Self> {
        data.try_into()
    }
}

impl LoadFromPath for ID {
    fn load_from_path(data: &[u8], path: &[u8]) -> crate::Result<Self> {
        let mut buf = [0; 64];
        HMAC_SHA512(data, path, &mut buf);

        let (id, _) = buf.split_at(24);

        id.try_into()
    }
}

impl VaultId {
    /// Create a new random `VaultId`.
    pub fn random<P: BoxProvider>() -> crate::Result<Self> {
        Ok(VaultId(ID::random::<P>()?))
    }

    /// Load a `VaultId` from some data.
    pub fn load(data: &[u8]) -> crate::Result<Self> {
        Ok(VaultId(ID::load(data)?))
    }
}

impl LoadFromPath for VaultId {
    fn load_from_path(data: &[u8], path: &[u8]) -> crate::Result<Self> {
        Ok(VaultId(ID::load_from_path(data, path)?))
    }
}

impl ClientId {
    /// Create a new random `ClientId`.
    pub fn random<P: BoxProvider>() -> crate::Result<Self> {
        Ok(ClientId(ID::random::<P>()?))
    }

    /// Load a `ClientId` from some data.
    pub fn load(data: &[u8]) -> crate::Result<Self> {
        Ok(ClientId(ID::load(data)?))
    }
}

impl LoadFromPath for ClientId {
    fn load_from_path(data: &[u8], path: &[u8]) -> crate::Result<Self> {
        Ok(ClientId(ID::load_from_path(data, path)?))
    }
}

impl TryFrom<&[u8]> for ID {
    type Error = crate::Error;

    fn try_from(bs: &[u8]) -> Result<Self, Self::Error> {
        if bs.len() != 24 {
            return Err(crate::Error::IDError);
        }

        let mut tmp = [0; 24];
        tmp.copy_from_slice(bs);
        Ok(Self(tmp))
    }
}

impl TryFrom<Vec<u8>> for ID {
    type Error = crate::Error;

    fn try_from(bs: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bs.as_slice())
    }
}

impl TryFrom<Vec<u8>> for ClientId {
    type Error = crate::Error;

    fn try_from(bs: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(ClientId(bs.try_into()?))
    }
}

impl TryFrom<&[u8]> for ClientId {
    type Error = crate::Error;

    fn try_from(bs: &[u8]) -> Result<Self, Self::Error> {
        Ok(ClientId(bs.try_into()?))
    }
}

impl Debug for ClientId {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Client({})", self.0.as_ref().base64())
    }
}

impl TryFrom<Vec<u8>> for VaultId {
    type Error = crate::Error;

    fn try_from(bs: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(VaultId(bs.try_into()?))
    }
}

impl TryFrom<&[u8]> for VaultId {
    type Error = crate::Error;

    fn try_from(bs: &[u8]) -> Result<Self, Self::Error> {
        Ok(VaultId(bs.try_into()?))
    }
}

impl Debug for VaultId {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Vault({})", self.0.as_ref().base64())
    }
}

impl Into<Vec<u8>> for VaultId {
    fn into(self) -> Vec<u8> {
        self.0 .0.to_vec()
    }
}

impl AsRef<[u8]> for VaultId {
    fn as_ref(&self) -> &[u8] {
        &self.0 .0
    }
}

impl Into<Vec<u8>> for ClientId {
    fn into(self) -> Vec<u8> {
        self.0 .0.to_vec()
    }
}

impl AsRef<[u8]> for ClientId {
    fn as_ref(&self) -> &[u8] {
        &self.0 .0
    }
}

impl Into<String> for ClientId {
    fn into(self) -> String {
        self.0.as_ref().base64()
    }
}

impl Into<String> for VaultId {
    fn into(self) -> String {
        self.0.as_ref().base64()
    }
}
