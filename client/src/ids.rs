// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use engine::vault::{Base64Encodable, BoxProvider};

use std::{
    convert::{TryFrom, TryInto},
    fmt::{self, Debug, Formatter},
    hash::Hash,
};

#[repr(transparent)]
#[derive(Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClientId(ID);

#[repr(transparent)]
#[derive(Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub struct VaultId(ID);

#[repr(transparent)]
#[derive(Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
struct ID([u8; 24]);

impl AsRef<[u8]> for ID {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Debug for ID {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Chain({})", self.0.base64())
    }
}

impl ID {
    pub fn random<P: BoxProvider>() -> crate::Result<Self> {
        let mut buf = [0; 24];
        P::random_buf(&mut buf)?;

        Ok(Self(buf))
    }

    #[allow(dead_code)]
    pub fn load(data: &[u8]) -> crate::Result<Self> {
        data.try_into()
    }
}

impl VaultId {
    pub fn random<P: BoxProvider>() -> crate::Result<Self> {
        Ok(VaultId(ID::random::<P>()?))
    }
}

impl ClientId {
    pub fn random<P: BoxProvider>() -> crate::Result<Self> {
        Ok(ClientId(ID::random::<P>()?))
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
