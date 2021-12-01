// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Synchronization Actor.
//!
//! The synchronization actor acts as a logical mediator between the network actor,
//! the snapshot actor and the registry and is stateless by default, querying the registry
//! for current values.

use actix::{Actor, Context, Handler, Message};
use serde::{Deserialize, Serialize};

use super::Registry;
use crate::{utils::EntryShape, Location};
use actix::Addr;
use engine::vault::ClientId;
use messages::*;
use std::collections::HashMap;
use thiserror::Error as DeriveError;

pub mod messages {
    use serde::{Deserialize, Serialize};
    use stronghold_utils::GuardDebug;

    use super::*;

    /// Container object for public / private key
    /// encrypted data. The `key` fields contains
    /// an encrypted key by a public key, provided
    /// by the requesting peer.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct EncryptedData {
        pub key: Vec<u8>,
        pub data: Vec<u8>,
    }

    #[derive(Clone, GuardDebug, Serialize, Deserialize)]
    pub struct FullSynchronizationRemote {
        pub peer: Option<Vec<u8>>,
        // pub id: ClientId,
        pub key: Vec<u8>,
    }
    #[derive(Clone, GuardDebug, Serialize, Deserialize)]
    pub struct CalculateShapeLocal {}

    #[derive(Clone, GuardDebug, Serialize, Deserialize)]
    pub struct CalculateShapeRemote {}

    #[derive(Clone, GuardDebug, Serialize, Deserialize)]
    pub struct PartialSynchronizationRemote {
        pub peer: Option<Vec<u8>>,
        // pub id: ClientId,
        pub key: Vec<u8>,
        pub sync_with: HashMap<Location, EntryShape>,
    }
    #[derive(Clone, GuardDebug, Serialize, Deserialize)]
    pub struct ComplementSynchronization {
        pub peer: Option<Vec<u8>>,
        // pub id: ClientId,
        pub key: Vec<u8>,
    }

    impl Message for FullSynchronizationRemote {
        type Result = Result<(ClientId, EncryptedData), SynchronizationError>;
    }

    impl Message for CalculateShapeRemote {
        type Result = Result<HashMap<Location, EntryShape>, SynchronizationError>;
    }

    impl Message for PartialSynchronizationRemote {
        type Result = Result<EncryptedData, SynchronizationError>;
    }

    impl Message for CalculateShapeLocal {
        type Result = Result<HashMap<Location, EntryShape>, SynchronizationError>;
    }

    impl Message for ComplementSynchronization {
        type Result = Result<EncryptedData, SynchronizationError>;
    }

    impl EncryptedData {
        pub fn from(key: Vec<u8>, data: Vec<u8>) -> Self {
            Self { data, key }
        }
    }
}

#[derive(DeriveError, Debug, Clone, Serialize, Deserialize)]
pub enum SynchronizationError {
    #[error("Input is invalid ({0})")]
    InvalidInput(String),
}

pub struct SynchronizationActor {
    // client: Option<Addr<SecureClient>>,
    // snapshot: Option<Addr<Snapshot>>,
    registry: Addr<Registry>,
}

impl Actor for SynchronizationActor {
    type Context = Context<Self>;
}

impl SynchronizationActor {
    pub fn new(registry: Addr<Registry>) -> Self {
        SynchronizationActor { registry }
    }
}

impl Handler<FullSynchronizationRemote> for SynchronizationActor {
    type Result = Result<(ClientId, EncryptedData), SynchronizationError>;

    #[allow(unused_variables)]
    fn handle(&mut self, msg: FullSynchronizationRemote, ctx: &mut Self::Context) -> Self::Result {
        // get current peer_id for client_id mapping
        // request access
        todo!()
    }
}
#[allow(unused_variables)]
impl Handler<CalculateShapeLocal> for SynchronizationActor {
    type Result = Result<HashMap<Location, EntryShape>, SynchronizationError>;

    fn handle(&mut self, msg: CalculateShapeLocal, ctx: &mut Self::Context) -> Self::Result {
        // get current target to get client_id
        todo!()
    }
}
#[allow(unused_variables)]
impl Handler<CalculateShapeRemote> for SynchronizationActor {
    type Result = Result<HashMap<Location, EntryShape>, SynchronizationError>;

    fn handle(&mut self, msg: CalculateShapeRemote, ctx: &mut Self::Context) -> Self::Result {
        // get current target to get client_id
        todo!()
    }
}
#[allow(unused_variables)]
impl Handler<PartialSynchronizationRemote> for SynchronizationActor {
    type Result = Result<EncryptedData, SynchronizationError>;

    fn handle(&mut self, msg: PartialSynchronizationRemote, ctx: &mut Self::Context) -> Self::Result {
        // get current peer_id for client_id mapping
        // request access
        todo!()
    }
}
#[allow(unused_variables)]
impl Handler<ComplementSynchronization> for SynchronizationActor {
    type Result = Result<EncryptedData, SynchronizationError>;

    fn handle(&mut self, msg: ComplementSynchronization, ctx: &mut Self::Context) -> Self::Result {
        // get current peer_id for client_id mapping
        // request access
        todo!()
    }
}
