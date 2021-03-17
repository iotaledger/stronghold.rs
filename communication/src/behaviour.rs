// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! # P2PNetworkBehaviour
//!
//! This module implements the [`P2PNetworkBehaviour`] that creates a [`ExpandedSwarm`] as entry point for all
//! communication. It provides an interface to send request/ responses to other peers, manage the known peers, and poll
//! for incoming events.
//!
//!
//! # Example
//!
//! The below example initiates, and polls from a Swarm, and reponds to each incoming Ping with a Pong.
//!
//! ```no_run
//! use async_std::task;
//! use core::ops::Deref;
//! use libp2p::identity::Keypair;
//! use serde::{Deserialize, Serialize};
//! use stronghold_communication::behaviour::{BehaviourConfig, P2PEvent, P2PNetworkBehaviour, P2PReqResEvent};
//!
//! #[derive(Debug, Clone, Serialize, Deserialize)]
//! pub enum Request {
//!     Ping,
//! }
//!
//! #[derive(Debug, Clone, Serialize, Deserialize)]
//! pub enum Response {
//!     Pong,
//! }
//!
//! let local_keys = Keypair::generate_ed25519();
//! let config = BehaviourConfig::default();
//! let mut swarm =
//!     P2PNetworkBehaviour::<Request, Response>::init_swarm(local_keys, config).expect("Init swarm failed.");
//!
//! task::block_on(async {
//!     loop {
//!         if let P2PEvent::RequestResponse(boxed_event) = swarm.next().await {
//!             if let P2PReqResEvent::Req {
//!                 peer_id,
//!                 request_id,
//!                 request: Request::Ping,
//!             } = boxed_event.deref().clone()
//!             {
//!                 let res = swarm.send_response(request_id, Response::Pong);
//!                 if res.is_err() {
//!                     break;
//!                 }
//!             }
//!         }
//!     }
//! });
//! ```

mod protocol;
mod types;

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
pub use protocol::MessageEvent;
use protocol::{MessageCodec, MessageProtocol};
use std::collections::HashMap;
use thiserror::Error as DeriveError;
pub use types::*;

/// Error upon creating a new [`P2PNetworkBehaviour`]
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

/// Configuration for initiating the [`P2PNetworkBehaviour`].
#[derive(Debug, Clone)]
pub struct BehaviourConfig {
    /// Timeout for outgoing requests until a [`P2POutboundFailure::Timeout`] is emitted.
    /// If none is specified, it defaults to 10s.
    timeout: Option<Duration>,
    /// Duration to keep an idle connection alive when no Request or Response is send.
    /// If none is specified, it defaults to 10s.
    keep_alive: Option<Duration>,
}

impl BehaviourConfig {
    pub fn new(timeout: Option<Duration>, keep_alive: Option<Duration>) -> Self {
        BehaviourConfig { timeout, keep_alive }
    }
}

impl Default for BehaviourConfig {
    fn default() -> Self {
        BehaviourConfig {
            timeout: None,
            keep_alive: None,
        }
    }
}

/// The [`P2PNetworkBehaviour`] determines the behaviour of the p2p-network.
/// It combines the following protocols from libp2p
/// - mDNS for peer discovery within the local network
/// - identify-protocol to receive identifying information of the remote peer
/// - RequestResponse Protocol for sending generic request `Req` and response `Res` messages
///
/// The P2PNetworkBehaviour itself is only effective if a new [`ExpandedSwarm`] is created for it, this
/// swarm is the entry point for all communication to remote peers, and contains the current state.
///
/// The [`P2PNetworkBehaviour`] implements a custom poll method that creates [`P2PEvent`]s from the events of the
/// different protocols, it can be polled with the `next()` or `next_event()` methods of the [`ExpandedSwarm`].
#[derive(NetworkBehaviour)]
#[behaviour(out_event = "P2PEvent<Req, Res>", poll_method = "poll")]
pub struct P2PNetworkBehaviour<Req: MessageEvent, Res: MessageEvent> {
    #[cfg(feature = "mdns")]
    mdns: Mdns,
    identify: Identify,
    msg_proto: RequestResponse<MessageCodec<Req, Res>>,
    #[behaviour(ignore)]
    peers: HashMap<PeerId, Vec<Multiaddr>>,
    #[behaviour(ignore)]
    events: Vec<P2PEvent<Req, Res>>,
    #[behaviour(ignore)]
    response_channels: HashMap<RequestId, ResponseChannel<Res>>,
}

impl<Req: MessageEvent, Res: MessageEvent> P2PNetworkBehaviour<Req, Res> {
    /// Creates a new [`P2PNetworkBehaviour`] and returns the swarm for it.
    /// The returned [`Swarm<P2PNetworkBehaviour>`] is the entry point for all communication with
    /// remote peers, i.g. to send requests and responses.
    /// Additionally to the methods of the [`P2PNetworkBehaviour`] there is a range of [`libp2p::ExpandedSwarm`]
    /// functions that can be used for swarm interaction like dialing a new peer.
    ///
    ///
    /// # Example
    /// ```no_run
    /// use libp2p::identity::Keypair;
    /// use serde::{Deserialize, Serialize};
    /// use stronghold_communication::behaviour::{BehaviourConfig, P2PNetworkBehaviour};
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
    /// let config = BehaviourConfig::default();
    /// let mut swarm =
    ///     P2PNetworkBehaviour::<Request, Response>::init_swarm(local_keys, config).expect("Init swarm failed.");
    /// ```
    pub fn init_swarm(
        local_keys: Keypair,
        config: BehaviourConfig,
    ) -> Result<Swarm<P2PNetworkBehaviour<Req, Res>>, BehaviourError> {
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
            if let Some(timeout) = config.timeout {
                cfg.set_request_timeout(timeout);
            }
            if let Some(keep_alive) = config.keep_alive {
                cfg.set_connection_keep_alive(keep_alive);
            }
            let protocols = iter::once((MessageProtocol(), ProtocolSupport::Full));
            RequestResponse::new(MessageCodec::<Req, Res>::default(), protocols, cfg)
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
    ) -> Poll<NetworkBehaviourAction<TEv, P2PEvent<Req, Res>>> {
        if !self.events.is_empty() {
            return Poll::Ready(NetworkBehaviourAction::GenerateEvent(self.events.remove(0)));
        }
        Poll::Pending
    }

    pub fn add_peer_addr(&mut self, peer_id: PeerId, addr: Multiaddr) {
        if let Some(addrs) = self.peers.get_mut(&peer_id) {
            if !addrs.contains(&addr) {
                addrs.push(addr);
            }
        } else {
            self.peers.insert(peer_id, vec![addr]);
        }
    }

    pub fn remove_peer_addr(&mut self, peer_id: &PeerId, addr: &Multiaddr) {
        if let Some(addrs) = self.peers.get_mut(peer_id) {
            addrs.retain(|a| a != addr);
        }
    }

    pub fn remove_peer(&mut self, peer_id: &PeerId) -> Option<Vec<Multiaddr>> {
        self.peers.remove(peer_id)
    }

    pub fn get_peer_addr(&self, peer_id: &PeerId) -> Option<&Vec<Multiaddr>> {
        self.peers.get(peer_id)
    }

    pub fn get_all_peers(&self) -> Vec<&PeerId> {
        self.peers.keys().collect()
    }

    #[cfg(feature = "mdns")]
    /// Get the peers discovered by mdns
    pub fn get_active_mdns_peers(&mut self) -> Vec<&PeerId> {
        self.mdns.discovered_nodes().collect()
    }

    pub fn send_request(&mut self, peer_id: &PeerId, request: Req) -> RequestId {
        self.msg_proto.send_request(peer_id, request)
    }

    pub fn send_response(&mut self, request_id: RequestId, response: Res) -> Result<(), Res> {
        let channel = self
            .response_channels
            .remove(&request_id)
            .ok_or_else(|| response.clone())?;
        self.msg_proto.send_response(channel, response)
    }
}

#[cfg(feature = "mdns")]
impl<Req: MessageEvent, Res: MessageEvent> NetworkBehaviourEventProcess<MdnsEvent> for P2PNetworkBehaviour<Req, Res> {
    // Called when `mdns` produces an event.
    fn inject_event(&mut self, event: MdnsEvent) {
        match event {
            MdnsEvent::Discovered(list) => {
                for (peer_id, multiaddr) in list {
                    self.add_peer_addr(peer_id, multiaddr);
                }
            }
            MdnsEvent::Expired(list) => {
                for (peer_id, multiaddr) in list {
                    self.remove_peer_addr(&peer_id, &multiaddr);
                }
            }
        }
    }
}

impl<Req: MessageEvent, Res: MessageEvent> NetworkBehaviourEventProcess<RequestResponseEvent<Req, Res>>
    for P2PNetworkBehaviour<Req, Res>
{
    // Called when a request or response was received.
    fn inject_event(&mut self, event: RequestResponseEvent<Req, Res>) {
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

impl<Req: MessageEvent, Res: MessageEvent> NetworkBehaviourEventProcess<IdentifyEvent>
    for P2PNetworkBehaviour<Req, Res>
{
    // Called when `identify` produces an event.
    fn inject_event(&mut self, event: IdentifyEvent) {
        if let IdentifyEvent::Received {
            peer_id,
            ref info,
            observed_addr: _,
        } = event
        {
            if self.get_peer_addr(&peer_id).is_none() {
                for addr in &info.listen_addrs {
                    self.add_peer_addr(peer_id, addr.clone());
                }
            }
        }
        self.events.push(P2PEvent::from(event));
    }
}
