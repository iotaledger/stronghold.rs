// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use stronghold_utils::random as rnd;

#[derive(Default, PartialEq, Clone)]
pub struct Entity {
    pub id: usize,
    pub name: String,
    pub allowed: Vec<String>,
}
#[derive(PartialEq, Eq, Hash, Default, Clone)]
pub struct PeerId {
    pub id: Vec<u8>,
}

#[derive(PartialEq, Eq, Hash, Default, Clone)]
pub struct ClientId {
    pub id: Vec<u8>,
}

#[derive(PartialEq, Eq, Hash, Default, Clone, Debug)]
pub struct Location {
    pub chain_id: Vec<u8>,
    pub record_id: Vec<u8>,
}

impl AsRef<PeerId> for PeerId {
    fn as_ref(&self) -> &PeerId {
        self
    }
}

impl From<Vec<u8>> for PeerId {
    fn from(id: Vec<u8>) -> Self {
        PeerId { id }
    }
}

impl From<Vec<u8>> for ClientId {
    fn from(id: Vec<u8>) -> Self {
        ClientId { id }
    }
}

impl From<Vec<u8>> for Location {
    fn from(id: Vec<u8>) -> Self {
        Location {
            chain_id: id.clone(),
            record_id: id,
        }
    }
}

impl<const N: usize> From<&[u8; N]> for Location {
    fn from(id: &[u8; N]) -> Self {
        Location {
            chain_id: id.to_vec(),
            record_id: id.to_vec(),
        }
    }
}
impl<const N: usize> From<&[u8; N]> for PeerId {
    fn from(data: &[u8; N]) -> Self {
        PeerId { id: data.to_vec() }
    }
}

impl<const N: usize> From<&[u8; N]> for ClientId {
    fn from(data: &[u8; N]) -> Self {
        Self { id: data.to_vec() }
    }
}

// clippy throws an error, because this implementation is only used
// inside a test context, but nowhere else.
#[allow(dead_code)]
impl Location {
    pub fn random() -> Self {
        Location {
            chain_id: rnd::bytestring(64),
            record_id: rnd::bytestring(64),
        }
    }
}
