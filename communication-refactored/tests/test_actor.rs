// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "actor")]

use actix::prelude::*;
use communication_refactored::{
    actor::{messages, CommunicationActor, GetClient},
    firewall::{Rule, RuleDirection},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Message)]
#[rtype(result = "Response")]
struct Request;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Response;

struct Client;
impl Actor for Client {
    type Context = Context<Self>;
}

impl Handler<Request> for Client {
    type Result = MessageResult<Request>;
    fn handle(&mut self, _msg: Request, _ctx: &mut Self::Context) -> Self::Result {
        MessageResult(Response)
    }
}

struct Registry {
    client: Addr<Client>,
}

impl Actor for Registry {
    type Context = Context<Self>;
}

impl Handler<GetClient<Request, Client>> for Registry {
    type Result = MessageResult<GetClient<Request, Client>>;
    fn handle(&mut self, _msg: GetClient<Request, Client>, _ctx: &mut Self::Context) -> Self::Result {
        MessageResult(self.client.clone())
    }
}

#[actix_rt::test]
async fn test_actor() {
    let client_a = Client.start();
    let registry_a = Registry { client: client_a }.start();
    let comms_a = CommunicationActor::new(registry_a).await.unwrap().start();
    let a_id = comms_a.send(messages::GetLocalPeerId).await.unwrap();
    let a_address = comms_a
        .send(messages::StartListening { address: None })
        .await
        .unwrap()
        .unwrap();
    let set_firewall_msg = messages::SetFirewallDefault {
        direction: RuleDirection::Inbound,
        rule: Rule::AllowAll,
    };
    comms_a.send(set_firewall_msg).await.unwrap();

    let client_b = Client.start();
    let registry_b = Registry { client: client_b }.start();
    let comms_b = CommunicationActor::new(registry_b).await.unwrap().start();

    let add_peer_msg = messages::AddPeerAddr {
        peer: a_id,
        address: a_address,
    };
    comms_b.send(add_peer_msg).await.unwrap();

    let set_firewall_msg = messages::SetFirewallRule {
        peer: a_id,
        direction: RuleDirection::Outbound,
        rule: Rule::AllowAll,
    };
    comms_b.send(set_firewall_msg).await.unwrap();

    let res = comms_b.send(messages::SendRequest::new(a_id, Request)).await.unwrap();
    assert!(res.is_ok(), "Unexpected Error: {:?}", res);
}
