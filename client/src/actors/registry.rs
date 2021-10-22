// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Registry Actor
//!
//! The registry actor keeps record of all client actors
//! bound to a unique `client_id`. [`SecureClient`] actors can
//! be added, removed or queried for their [`actix::Addr`].
//! The registry can also be queried for the snapshot actor.

use actix::{Actor, Addr, Context, Handler, Message, Supervised};
use engine::vault::ClientId;
use std::collections::HashMap;

#[cfg(feature = "p2p")]
use super::p2p::NetworkActor;
use crate::{actors::SecureClient, state::snapshot::Snapshot};

pub mod messages {
    use super::*;

    pub struct SpawnClient {
        pub id: ClientId,
    }

    impl Message for SpawnClient {
        type Result = Addr<SecureClient>;
    }

    pub struct SwitchTarget {
        pub id: ClientId,
    }

    impl Message for SwitchTarget {
        type Result = Option<Addr<SecureClient>>;
    }

    pub struct RemoveClient {
        pub id: ClientId,
    }

    impl Message for RemoveClient {
        type Result = Option<Addr<SecureClient>>;
    }

    pub struct GetTarget;

    impl Message for GetTarget {
        type Result = Option<Addr<SecureClient>>;
    }

    pub struct GetClient {
        pub id: ClientId,
    }

    impl Message for GetClient {
        type Result = Option<Addr<SecureClient>>;
    }

    pub struct GetSnapshot;

    impl Message for GetSnapshot {
        type Result = Addr<Snapshot>;
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
#[derive(Default)]
pub struct Registry {
    clients: HashMap<ClientId, Addr<SecureClient>>,
    current_target: Option<ClientId>,
    snapshot: Option<Addr<Snapshot>>,
    #[cfg(feature = "p2p")]
    network: Option<Addr<NetworkActor>>,
}

impl Supervised for Registry {}

impl Actor for Registry {
    type Context = Context<Self>;
}

impl Handler<messages::SpawnClient> for Registry {
    type Result = Addr<SecureClient>;

    fn handle(&mut self, msg: messages::SpawnClient, ctx: &mut Self::Context) -> Self::Result {
        if let Some(addr) = self.clients.get(&msg.id) {
            return addr.clone();
        }
        let addr = SecureClient::new(msg.id).start();
        self.clients.insert(msg.id, addr);

        Self::handle(self, messages::SwitchTarget { id: msg.id }, ctx).unwrap()
    }
}

impl Handler<messages::GetTarget> for Registry {
    type Result = Option<Addr<SecureClient>>;

    fn handle(&mut self, _msg: messages::GetTarget, _ctx: &mut Self::Context) -> Self::Result {
        self.current_target.and_then(|id| self.clients.get(&id)).cloned()
    }
}

impl Handler<messages::GetClient> for Registry {
    type Result = Option<Addr<SecureClient>>;

    fn handle(&mut self, msg: messages::GetClient, _ctx: &mut Self::Context) -> Self::Result {
        self.clients.get(&msg.id).cloned()
    }
}

impl Handler<messages::SwitchTarget> for Registry {
    type Result = Option<Addr<SecureClient>>;

    fn handle(&mut self, msg: messages::SwitchTarget, _ctx: &mut Self::Context) -> Self::Result {
        let addr = self.clients.get(&msg.id)?;
        self.current_target = Some(msg.id);
        Some(addr.clone())
    }
}

impl Handler<messages::RemoveClient> for Registry {
    type Result = Option<Addr<SecureClient>>;

    fn handle(&mut self, msg: messages::RemoveClient, _ctx: &mut Self::Context) -> Self::Result {
        self.clients.remove(&msg.id)
    }
}

impl Handler<messages::GetSnapshot> for Registry {
    type Result = Addr<Snapshot>;

    fn handle(&mut self, _: messages::GetSnapshot, _: &mut Self::Context) -> Self::Result {
        self.snapshot.get_or_insert(Snapshot::default().start()).clone()
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
