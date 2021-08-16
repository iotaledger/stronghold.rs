// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! An example implementation of how the Communication Actor can be used to enable communication between two different
//! actor systems.
//!
//! The goal is to send a `Question` from system A to the Client of a different system B, and receive its response:
//! ```
//! Question -> CommunicationActor A --- Swarm --> CommunicationActor B --> Client B
//!                                                                           |
//! Response <- CommunicationActor A <-- Swarm --- CommunicationActor B <-----|
//! ```
//!
//! The message is sent to Communication Actor A by using the `ask` pattern of riker.rs, which spawns a temporary
//! AskActor that sends the request to the communication actor and return upon a response.

use async_std::task;
use communication::{
    actor::{
        CommunicationActor, CommunicationActorConfig, CommunicationRequest, CommunicationResults, FirewallPermission,
        PermissionValue, RequestPermissions, VariantPermission,
    },
    behaviour::BehaviourConfig,
    libp2p::{Keypair, PeerId},
};
use riker::actors::*;
use stronghold_utils::ask;

use futures::future;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize, RequestPermissions)]
pub struct Question(String);

impl fmt::Display for Question {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Answer(String);

impl fmt::Display for Answer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Debug)]
struct Client;

impl ActorFactory for Client {
    fn create() -> Self {
        Client
    }
}

impl Actor for Client {
    type Msg = Question;

    fn recv(&mut self, _ctx: &Context<Self::Msg>, _msg: Self::Msg, sender: Sender) {
        sender
            .expect("Sender should exists")
            .try_tell(Answer(format!("{}", 42)), None)
            .expect("Sender should receive the response");
    }
}

// Init actor system
fn init_system(sys: &ActorSystem) -> Result<(PeerId, ActorRef<CommunicationRequest<Question, Question>>), String> {
    // Keypair for the noise-protocol authentication
    let keys = Keypair::generate_ed25519();
    let peer_id = PeerId::from(keys.public());

    // Use default config for the network behaviour
    let behaviour_config = BehaviourConfig::default();

    // Spawn client actor to respond to incoming requests
    let client = sys
        .actor_of::<Client>("client")
        .map_err(|e| format!("Failed to create client actor: {:?}", e))?;

    // Configure the firewall to allow all requests
    let actor_config = CommunicationActorConfig {
        client,
        firewall_default_in: FirewallPermission::all(),
        firewall_default_out: FirewallPermission::all(),
    };

    // Spawn communication actor
    let communication_actor = sys
        .actor_of_args::<CommunicationActor<_, Answer, _, _>, _>(
            "communication",
            (keys, actor_config, behaviour_config),
        )
        .map_err(|e| format!("Failed to create communication actor: {:?}", e))?;
    Ok((peer_id, communication_actor))
}

fn main() -> Result<(), String> {
    let question = "What is the answer to the ultimate question of life, the universe, and everything?".to_string();
    println!("\n\n{}\n\n", question);

    // Creat system A that attempts to send a request to the client of system B.
    let sys_a = ActorSystem::new().map_err(|e| format!("Failed to create actor system: {:?}", e))?;
    let (_, communication_actor_a) = init_system(&sys_a)?;

    // Creat system B that should receive the question and response to it.
    let sys_b = ActorSystem::new().map_err(|e| format!("Failed to create actor system: {:?}", e))?;
    let (peer_b, communication_actor_b) = init_system(&sys_b)?;

    let answer = task::block_on::<_, Result<Answer, String>>(async {
        // Communication Actor B starts listening for incoming requests
        let addr_b = match ask(
            &sys_b,
            &communication_actor_b,
            CommunicationRequest::StartListening(None),
        )
        .await
        {
            CommunicationResults::<Answer>::StartListeningResult(Ok(addr)) => Ok(addr),
            CommunicationResults::<Answer>::StartListeningResult(Err(())) => {
                Err("Failed to start listening".to_string())
            }
            _ => unreachable!("StartListening always returns StartListeningResult."),
        }?;

        // Communication Actor A establishes a connection to Communication Actor B
        match ask(
            &sys_a,
            &communication_actor_a,
            CommunicationRequest::AddPeer {
                addr: Some(addr_b),
                peer_id: peer_b,
                is_relay: None,
            },
        )
        .await
        {
            CommunicationResults::<Answer>::AddPeerResult(Ok(_)) => Ok(()),
            CommunicationResults::<Answer>::AddPeerResult(Err(e)) => {
                Err(format!("Failed to establish connection: {:?}", e))
            }
            _ => unreachable!("EstablishConnection always returns EstablishConnectionResult."),
        }?;

        // Communication Actor A sends request over swarm to Communication Actor B, Communication Actor B forwards it to
        // the Client and returns their response.
        let answer = match ask(
            &sys_a,
            &communication_actor_a,
            CommunicationRequest::RequestMsg {
                peer_id: peer_b,
                request: Question(question),
            },
        )
        .await
        {
            CommunicationResults::<Answer>::RequestMsgResult(Ok(answer)) => Ok(answer),
            CommunicationResults::<Answer>::RequestMsgResult(Err(e)) => {
                Err(format!("Failed to send request or receive response: {:?}", e))
            }
            _ => unreachable!("RequestMsg always returns RequestMsgResult."),
        }?;

        // Shutdown both actor systems
        let (..) = future::join(sys_a.shutdown(), sys_b.shutdown()).await;
        Ok(answer)
    })?;

    println!(
        "\n\nThe answer to the ultimate question of life, the universe, and everything is {}.\n\n",
        answer
    );
    Ok(())
}
