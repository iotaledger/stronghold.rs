// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Registry Actor
//!
//! The registry actor keeps record of all client actors
//! bound to a unique `client_id`. [`SecureClient`] actors can
//! be added, removed or queried for their [`actix::Addr`].
//! The registry can also be queried for the snapshot actor.

#![allow(clippy::redundant_pattern_matching)]
use actix::{Actor, Addr, Context, Handler, Message, Supervised, SystemService};
use engine::vault::ClientId;
use std::collections::HashMap;
use thiserror::Error as ErrorType;

use crate::{actors::SecureClient, state::snapshot::Snapshot};

#[derive(Debug, ErrorType)]
pub enum RegistryError {
    #[error("No Client Present By Id ({0})")]
    NoClientPresentById(String),

    #[error("Client Already Present By Id ({0})")]
    ClientAlreadyPresentById(String),
}

pub mod messages {

    use super::*;

    pub struct InsertClient {
        pub id: ClientId,
    }

    impl Message for InsertClient {
        type Result = Result<Addr<SecureClient>, RegistryError>;
    }

    pub struct RemoveClient {
        pub id: ClientId,
    }

    impl Message for RemoveClient {
        type Result = Result<(), RegistryError>;
    }

    pub struct GetClient {
        pub id: ClientId,
    }

    impl Message for GetClient {
        type Result = Option<Addr<SecureClient>>;
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
}

/// Registry [`Actor`], that owns [`Client`] actors, and manages them. The registry
/// can be modified
#[derive(Default)]
pub struct Registry {
    clients: HashMap<ClientId, Addr<SecureClient>>,
    snapshot: Option<Addr<Snapshot>>,
}

impl Supervised for Registry {}

impl Actor for Registry {
    type Context = Context<Self>;
}

/// For synchronized access across multiple clients, the [`Registry`]
/// will run as a service.
impl SystemService for Registry {}

impl Handler<messages::HasClient> for Registry {
    type Result = bool;

    fn handle(&mut self, msg: messages::HasClient, _ctx: &mut Self::Context) -> Self::Result {
        self.clients.contains_key(&msg.id)
    }
}

impl Handler<messages::InsertClient> for Registry {
    type Result = Result<Addr<SecureClient>, RegistryError>;

    fn handle(&mut self, msg: messages::InsertClient, _ctx: &mut Self::Context) -> Self::Result {
        if let Some(_) = self.clients.get(&msg.id) {
            return Err(RegistryError::ClientAlreadyPresentById(msg.id.into()));
        }

        let addr = SecureClient::new(msg.id).start();
        self.clients.insert(msg.id, addr.clone());
        Ok(addr)
    }
}

impl Handler<messages::GetClient> for Registry {
    type Result = Option<Addr<SecureClient>>;

    fn handle(&mut self, msg: messages::GetClient, _ctx: &mut Self::Context) -> Self::Result {
        if let Some(client) = self.clients.get(&msg.id) {
            return Some(client.clone());
        }
        None
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

#[cfg(test)]
mod tests {

    use super::*;

    #[actix::test]
    async fn test_insert_client() {
        let registry = Registry::default().start();

        for d in 'a'..'z' {
            let format_str = format!("{}", d).repeat(24);
            let id_str = format_str.as_str().as_bytes();
            let n = registry
                .send(messages::InsertClient {
                    id: ClientId::load(id_str).unwrap(),
                })
                .await;

            assert!(n.is_ok());
        }
    }

    #[actix::test]
    async fn test_get_client() {
        let registry = Registry::default().start();

        for d in 'a'..'z' {
            let format_str = format!("{}", d).repeat(24);
            let id_str = format_str.as_str().as_bytes();
            assert!(registry
                .send(messages::InsertClient {
                    id: ClientId::load(id_str).unwrap(),
                })
                .await
                .is_ok());
        }

        assert!(registry
            .send(messages::GetClient {
                id: ClientId::load("b".repeat(24).as_bytes()).unwrap(),
            })
            .await
            .is_ok());
    }

    #[actix::test]
    async fn test_remove_client() {
        let registry = Registry::default().start();

        for d in 'a'..'z' {
            let format_str = format!("{}", d).repeat(24);
            let id_str = format_str.as_str().as_bytes();
            assert!(registry
                .send(messages::InsertClient {
                    id: ClientId::load(id_str).unwrap(),
                })
                .await
                .is_ok());
        }

        if let Ok(result) = registry
            .send(messages::RemoveClient {
                id: ClientId::load("a".repeat(24).as_bytes()).unwrap(),
            })
            .await
        {
            assert!(result.is_ok())
        }
    }
}
