// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Registry Actor
//!
//! The registry actor keeps record of all client actors
//! bound to a unique `client_id`. [`SecureClient`] actors can
//! be added, removed or queried for their [`actix::Addr`].
//! The registry can also be queried for the snapshot actor.

#![allow(clippy::redundant_pattern_matching)]
use actix::{Actor, Addr, Context, Handler, Message, Supervised};
use engine::vault::ClientId;
use std::collections::HashMap;
use thiserror::Error as ErrorType;

#[cfg(feature = "p2p")]
use super::p2p::NetworkActor;
use crate::{actors::SecureClient, internals, state::snapshot::Snapshot};

#[derive(Debug, ErrorType)]
pub enum RegistryError {
    #[error("No Client Present By Id ({0})")]
    NoClientPresentById(String),

    #[error("Client Already Present By Id ({0})")]
    ClientAlreadyPresentById(String),

    #[error("Network actor was already spawned")]
    NetworkAlreadySpawned,
}

pub mod messages {
    use super::*;

    pub struct SpawnClient {
        pub id: ClientId,
    }

    impl Message for SpawnClient {
        type Result = Result<Addr<SecureClient>, RegistryError>;
    }

    pub struct SwitchClient {
        pub id: ClientId,
    }

    impl Message for SwitchClient {
        type Result = Result<Addr<SecureClient>, RegistryError>;
    }

    pub struct RemoveClient {
        pub id: ClientId,
    }

    impl Message for RemoveClient {
        type Result = Result<(), RegistryError>;
    }

    pub struct GetClient;

    impl Message for GetClient {
        type Result = Addr<SecureClient>;
    }

    pub struct HasClient {
        pub id: ClientId,
    }

    impl Message for HasClient {
        type Result = bool;
    }

    pub struct GetSnapshot;

    impl Message for GetSnapshot {
        type Result = Option<Addr<Snapshot>>;
    }

    pub struct GetAllClients;

    impl Message for GetAllClients {
        type Result = Vec<(ClientId, Addr<SecureClient>)>;
    }

    #[cfg(feature = "p2p")]
    pub struct InsertNetwork {
        pub addr: Addr<NetworkActor>,
    }

    #[cfg(feature = "p2p")]
    impl Message for InsertNetwork {
        type Result = ();
    }

    #[cfg(feature = "p2p")]
    pub struct GetNetwork;

    #[cfg(feature = "p2p")]
    impl Message for GetNetwork {
        type Result = Option<Addr<NetworkActor>>;
    }

    #[cfg(feature = "p2p")]
    pub struct StopNetwork;

    #[cfg(feature = "p2p")]
    impl Message for StopNetwork {
        type Result = bool;
    }
}

/// Registry [`Actor`], that owns [`Client`] actors, and manages them. The registry
/// can be modified
pub struct Registry {
    clients: HashMap<ClientId, Addr<SecureClient>>,
    current_client: ClientId,
    snapshot: Option<Addr<Snapshot>>,
    #[cfg(feature = "p2p")]
    network: Option<Addr<NetworkActor>>,
}

impl Default for Registry {
    fn default() -> Self {
        Registry {
            clients: HashMap::new(),
            current_client: ClientId::random::<internals::Provider>().unwrap(),
            snapshot: None,
            #[cfg(feature = "p2p")]
            network: None,
        }
    }
}

impl Supervised for Registry {}

impl Actor for Registry {
    type Context = Context<Self>;
}

impl Handler<messages::HasClient> for Registry {
    type Result = bool;

    fn handle(&mut self, msg: messages::HasClient, _ctx: &mut Self::Context) -> Self::Result {
        self.clients.contains_key(&msg.id)
    }
}

impl Handler<messages::SpawnClient> for Registry {
    type Result = Result<Addr<SecureClient>, RegistryError>;

    fn handle(&mut self, msg: messages::SpawnClient, ctx: &mut Self::Context) -> Self::Result {
        if let Some(_) = self.clients.get(&msg.id) {
            return Err(RegistryError::ClientAlreadyPresentById(msg.id.into()));
        }
        let addr = SecureClient::new(msg.id).start();
        self.clients.insert(msg.id, addr);

        <Self as Handler<messages::SwitchClient>>::handle(self, messages::SwitchClient { id: msg.id }, ctx)
    }
}

impl Handler<messages::GetClient> for Registry {
    type Result = Addr<SecureClient>;

    fn handle(&mut self, _msg: messages::GetClient, _ctx: &mut Self::Context) -> Self::Result {
        self.clients
            .get(&self.current_client)
            .expect("Current Client is always present")
            .clone()
    }
}

impl Handler<messages::SwitchClient> for Registry {
    type Result = Result<Addr<SecureClient>, RegistryError>;

    fn handle(&mut self, msg: messages::SwitchClient, _ctx: &mut Self::Context) -> Self::Result {
        let addr = self
            .clients
            .get(&msg.id)
            .ok_or_else(|| RegistryError::NoClientPresentById(msg.id.into()))?;
        self.current_client = msg.id;
        Ok(addr.clone())
    }
}

impl Handler<messages::RemoveClient> for Registry {
    type Result = Result<(), RegistryError>;

    fn handle(&mut self, msg: messages::RemoveClient, _ctx: &mut Self::Context) -> Self::Result {
        match self.clients.remove(&msg.id) {
            Some(_) => Ok(()),
            None => Err(RegistryError::NoClientPresentById(msg.id.into())),
        }
    }
}

impl Handler<messages::GetSnapshot> for Registry {
    type Result = Option<Addr<Snapshot>>;

    fn handle(&mut self, _: messages::GetSnapshot, _: &mut Self::Context) -> Self::Result {
        Some(self.snapshot.get_or_insert(Snapshot::default().start()).clone())
    }
}

impl Handler<messages::GetAllClients> for Registry {
    type Result = Vec<(ClientId, Addr<SecureClient>)>;

    fn handle(&mut self, _: messages::GetAllClients, _: &mut Self::Context) -> Self::Result {
        let mut result = Vec::new();

        for (id, addr) in &self.clients {
            result.push((*id, addr.clone()));
        }
        result
    }
}

#[cfg(feature = "p2p")]
impl Handler<messages::InsertNetwork> for Registry {
    type Result = ();
    fn handle(&mut self, msg: messages::InsertNetwork, _ctx: &mut Self::Context) -> Self::Result {
        self.network = Some(msg.addr);
    }
}

#[cfg(feature = "p2p")]
impl Handler<messages::GetNetwork> for Registry {
    type Result = Option<Addr<NetworkActor>>;

    fn handle(&mut self, _: messages::GetNetwork, _: &mut Self::Context) -> Self::Result {
        self.network.clone()
    }
}

#[cfg(feature = "p2p")]
impl Handler<messages::StopNetwork> for Registry {
    type Result = bool;

    fn handle(&mut self, _: messages::StopNetwork, _: &mut Self::Context) -> Self::Result {
        // Dropping the only address of the network actor will stop the actor.
        // Upon stopping the actor, its `StrongholdP2p` instance will be dropped, which results in a graceful shutdown.
        self.network.take().is_some()
    }
}
