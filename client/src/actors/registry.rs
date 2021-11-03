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
use crate::state::{secure::SecureClient, snapshot::Snapshot};

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
}

#[cfg(feature = "p2p")]
pub mod p2p_messages {

    use super::*;

    pub struct InsertNetwork {
        pub addr: Addr<NetworkActor>,
    }

    impl Message for InsertNetwork {
        type Result = ();
    }

    pub struct GetNetwork;

    impl Message for GetNetwork {
        type Result = Option<Addr<NetworkActor>>;
    }

    pub struct RemoveNetwork;

    impl Message for RemoveNetwork {
        type Result = Option<Addr<NetworkActor>>;
    }
}

/// Registry [`Actor`], that owns [`SecureClient`] actors, and manages them. The registry
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
impl Handler<p2p_messages::InsertNetwork> for Registry {
    type Result = ();
    fn handle(&mut self, msg: p2p_messages::InsertNetwork, _ctx: &mut Self::Context) -> Self::Result {
        self.network = Some(msg.addr);
    }
}

#[cfg(feature = "p2p")]
impl Handler<p2p_messages::GetNetwork> for Registry {
    type Result = Option<Addr<NetworkActor>>;

    fn handle(&mut self, _: p2p_messages::GetNetwork, _: &mut Self::Context) -> Self::Result {
        self.network.clone()
    }
}

#[cfg(feature = "p2p")]
impl Handler<p2p_messages::RemoveNetwork> for Registry {
    type Result = Option<Addr<NetworkActor>>;

    fn handle(&mut self, _: p2p_messages::RemoveNetwork, _: &mut Self::Context) -> Self::Result {
        // Dropping the only address of the network actor will stop the actor.
        // Upon stopping the actor, its `StrongholdP2p` instance will be dropped, which results in a graceful shutdown.
        self.network.take()
    }
}
