// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod message;
mod protocol;

#[cfg(feature = "mdns")]
use async_std::task;
use core::{
    iter,
    result::Result,
    task::{Context, Poll},
    time::Duration,
};
#[cfg(feature = "mdns")]
use libp2p::mdns::{Mdns, MdnsEvent};
use libp2p::{
    core::{upgrade, Multiaddr, PeerId},
    dns::DnsConfig,
    identify::{Identify, IdentifyEvent},
    identity::Keypair,
    noise::{self, NoiseConfig},
    request_response::{
        ProtocolSupport, RequestId, RequestResponse, RequestResponseConfig, RequestResponseEvent,
        RequestResponseMessage, ResponseChannel,
    },
    swarm::{NetworkBehaviourAction, NetworkBehaviourEventProcess, PollParameters, Swarm},
    tcp::TcpConfig,
    websocket::WsConfig,
    yamux::YamuxConfig,
    NetworkBehaviour, Transport,
};
pub use message::*;
pub use protocol::MessageEvent;
use protocol::{MessageCodec, MessageProtocol};
use std::collections::HashMap;
use thiserror::Error as DeriveError;

/// Error upon creating a new NetworkBehaviour
#[derive(Debug, DeriveError)]
pub enum BehaviourError {
    /// Error on the transport layer
    #[error("Transport error: `{0}`")]
    TransportError(String),

    /// Error on upgrading the transport with noise authentication
    #[error("Noise authentic error: `{0}")]
    NoiseAuthenticError(String),

    /// Error creating new mDNS behaviour
    #[error("Mdns error: `{0}`")]
    MdnsError(String),
}

/// The `P2PNetworkBehaviour` determines the behaviour of the p2p-network.
/// It combines the following protocols from libp2p
/// - mDNS for peer discovery within the local network
/// - identify-protocol to receive identifying information of the remote peer
/// - RequestResponse Protocol for sending generic request `T` and response `U` messages
///
/// The P2PNetworkBehaviour itself is only useful when a new `Swarm` is created for it, and this
/// swarm is the entry point for all communication to remote peers, and contains the current state.
///
/// The `P2PNetworkBehaviour` implements a custom poll method that creates `P2PEvent`s from the events of the different
/// protocols, it can be polled with the `next()` or `next_event()` methods of `libp2p::swarm::ExpandedSwarm`.
#[derive(NetworkBehaviour)]
#[behaviour(out_event = "P2PEvent<T, U>", poll_method = "poll")]
pub struct P2PNetworkBehaviour<T: MessageEvent, U: MessageEvent> {
    #[cfg(feature = "mdns")]
    mdns: Mdns,
    identify: Identify,
    msg_proto: RequestResponse<MessageCodec<T, U>>,
    #[behaviour(ignore)]
    peers: HashMap<PeerId, Multiaddr>,
    #[behaviour(ignore)]
    events: Vec<P2PEvent<T, U>>,
    #[behaviour(ignore)]
    response_channels: HashMap<RequestId, ResponseChannel<U>>,
}

impl<T: MessageEvent, U: MessageEvent> P2PNetworkBehaviour<T, U> {
    /// Creates a new `P2PNetworkBehaviour` and returns the swarm for it.
    /// The returned `Swarm<P2PNetworkBehaviour>` is the entry point for all communication with
    /// remote peers, i.g. to send requests and responses.
    /// Additionally to the methods of the `P2PNetworkBehaviour` there is a range of `libp2p::Swarm`
    /// functions for swarm interaction, like dialing a new peer, that can be used.
    ///
    ///
    /// # Example
    /// ```no_run
    /// use libp2p::identity::Keypair;
    /// use serde::{Deserialize, Serialize};
    /// use stronghold_communication::behaviour::P2PNetworkBehaviour;
    ///
    /// #[derive(Debug, Clone, Serialize, Deserialize)]
    /// pub enum Request {
    ///     Ping,
    /// }
    ///
    /// #[derive(Debug, Clone, Serialize, Deserialize)]
    /// pub enum Response {
    ///     Pong,
    /// }
    ///
    /// let local_keys = Keypair::generate_ed25519();
    /// let mut swarm = P2PNetworkBehaviour::<Request, Response>::init_swarm(local_keys).unwrap();
    /// ```
    pub fn init_swarm(local_keys: Keypair) -> Result<Swarm<P2PNetworkBehaviour<T, U>>, BehaviourError> {
        let local_peer_id = PeerId::from(local_keys.public());

        let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
            .into_authentic(&local_keys)
            .map_err(|e| BehaviourError::NoiseAuthenticError(format!("Could not create authentic keypair: {:?}", e)))?;
        // Use XX handshake pattern
        let noise = NoiseConfig::xx(noise_keys).into_authenticated();
        // Tcp layer with wrapper to resolve dns addresses
        let dns_transport = DnsConfig::new(TcpConfig::new())
            .map_err(|e| BehaviourError::TransportError(format!("Could not create transport: {:?}", e)))?;
        // The configured transport establishes connections via tcp with websockets as fallback, and
        // negotiates authentification and multiplexing on all connections
        let transport = dns_transport
            .clone()
            .or_transport(WsConfig::new(dns_transport))
            .upgrade(upgrade::Version::V1)
            .authenticate(noise)
            .multiplex(YamuxConfig::default())
            .boxed();

        // multicast DNS for peer discovery within a local network
        #[cfg(feature = "mdns")]
        let mdns = task::block_on(Mdns::new()).map_err(|e| BehaviourError::MdnsError(e.to_string()))?;
        // Identify protocol to receive identifying information of a remote peer once a connection
        // was established
        let identify = Identify::new(
            "/identify/0.1.0".into(),
            "stronghold-communication".into(),
            local_keys.public(),
        );
        // Enable Request- and Response-Messages with the generic MessageProtocol
        let msg_proto = {
            let mut cfg = RequestResponseConfig::default();
            cfg.set_connection_keep_alive(Duration::from_secs(60));
            let protocols = iter::once((MessageProtocol(), ProtocolSupport::Full));
            RequestResponse::new(MessageCodec::<T, U>::default(), protocols, cfg)
        };

        // The behaviour describes how the swarm handles events enables interacting with the
        // network
        let behaviour = P2PNetworkBehaviour {
            #[cfg(feature = "mdns")]
            mdns,
            msg_proto,
            identify,
            peers: HashMap::new(),
            events: Vec::new(),
            response_channels: HashMap::new(),
        };

        // The swarm manages a pool of connections established through the transport and drives the
        // NetworkBehaviour through emitting events triggered by activity on the managed connections.
        Ok(Swarm::new(transport, behaviour, local_peer_id))
    }

    // Custom function that is called when the swarm is polled
    fn poll<TEv>(
        &mut self,
        _cx: &mut Context<'_>,
        _params: &mut impl PollParameters,
    ) -> Poll<NetworkBehaviourAction<TEv, P2PEvent<T, U>>> {
        if !self.events.is_empty() {
            return Poll::Ready(NetworkBehaviourAction::GenerateEvent(self.events.remove(0)));
        }
        Poll::Pending
    }

    pub fn add_peer(&mut self, peer_id: PeerId, addr: Multiaddr) {
        self.peers.insert(peer_id, addr);
    }

    pub fn remove_peer(&mut self, peer_id: &PeerId) -> Option<Multiaddr> {
        self.peers.remove(peer_id)
    }

    pub fn get_peer_addr(&self, peer_id: &PeerId) -> Option<&Multiaddr> {
        self.peers.get(peer_id)
    }

    pub fn get_all_peers(&self) -> Vec<(&PeerId, &Multiaddr)> {
        self.peers.iter().collect()
    }

    pub fn send_request(&mut self, peer_id: &PeerId, request: T) -> RequestId {
        self.msg_proto.send_request(peer_id, request)
    }

    pub fn send_response(&mut self, response: U, request_id: RequestId) -> Result<(), U> {
        let channel = self
            .response_channels
            .remove(&request_id)
            .ok_or_else(|| response.clone())?;
        self.msg_proto.send_response(channel, response)
    }
    #[cfg(feature = "mdns")]
    /// Get the peers discovered by mdns
    pub fn get_active_mdns_peers(&mut self) -> Vec<&PeerId> {
        self.mdns.discovered_nodes().collect()
    }
}

#[cfg(feature = "mdns")]
impl<T: MessageEvent, U: MessageEvent> NetworkBehaviourEventProcess<MdnsEvent> for P2PNetworkBehaviour<T, U> {
    // Called when `mdns` produces an event.
    fn inject_event(&mut self, event: MdnsEvent) {
        match event {
            MdnsEvent::Discovered(list) => {
                for (peer_id, multiaddr) in list {
                    self.add_peer(peer_id, multiaddr);
                }
            }
            MdnsEvent::Expired(list) => {
                for (peer_id, _multiaddr) in list {
                    self.remove_peer(&peer_id);
                }
            }
        }
    }
}

impl<T: MessageEvent, U: MessageEvent> NetworkBehaviourEventProcess<RequestResponseEvent<T, U>>
    for P2PNetworkBehaviour<T, U>
{
    // Called when a request or response was received.
    fn inject_event(&mut self, event: RequestResponseEvent<T, U>) {
        let communication_event = if let RequestResponseEvent::Message {
            peer,
            message:
                RequestResponseMessage::Request {
                    request_id,
                    request,
                    channel,
                },
        } = event
        {
            self.response_channels.insert(request_id, channel);
            P2PEvent::RequestResponse(Box::new(P2PReqResEvent::Req {
                peer_id: peer,
                request_id,
                request,
            }))
        } else {
            P2PEvent::from(event)
        };
        self.events.push(communication_event);
    }
}

impl<T: MessageEvent, U: MessageEvent> NetworkBehaviourEventProcess<IdentifyEvent> for P2PNetworkBehaviour<T, U> {
    // Called when `identify` produces an event.
    fn inject_event(&mut self, event: IdentifyEvent) {
        if let IdentifyEvent::Received {
            peer_id,
            ref info,
            observed_addr: _,
        } = event
        {
            if self.get_peer_addr(&peer_id).is_none() {
                if let Some(addr) = info.listen_addrs.clone().pop() {
                    self.add_peer(peer_id, addr);
                }
            }
        }
        self.events.push(P2PEvent::from(event));
    }
}
