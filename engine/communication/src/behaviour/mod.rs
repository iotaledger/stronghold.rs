// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod protocol;
use crate::{
    error::{QueryError, QueryResult},
    message::{CommunicationEvent, ReqResEvent, Request, Response},
};
use core::{
    iter,
    str::FromStr,
    task::{Context, Poll},
};
#[cfg(feature = "mdns")]
use libp2p::mdns::{Mdns, MdnsEvent};
use libp2p::{
    build_tcp_ws_noise_mplex_yamux,
    core::{connection::ListenerId, Multiaddr, PeerId},
    identify::{Identify, IdentifyEvent},
    identity::Keypair,
    request_response::{
        ProtocolSupport, RequestId, RequestResponse, RequestResponseConfig, RequestResponseEvent,
        RequestResponseMessage, ResponseChannel,
    },
    swarm::{NetworkBehaviourAction, NetworkBehaviourEventProcess, PollParameters, Swarm},
    NetworkBehaviour,
};
use protocol::{MessageCodec, MessageProtocol};
// TODO: support no_std
use std::collections::btree_map::BTreeMap;
mod structs_proto {
    include!(concat!(env!("OUT_DIR"), "/structs.pb.rs"));
}

type ReqId = String;
type PeerStr = String;

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "CommunicationEvent", poll_method = "poll")]
pub struct P2PNetworkBehaviour {
    #[cfg(feature = "mdns")]
    mdns: Mdns,
    identify: Identify,
    msg_proto: RequestResponse<MessageCodec>,
    #[behaviour(ignore)]
    peers: BTreeMap<PeerStr, Multiaddr>,
    #[behaviour(ignore)]
    events: Vec<CommunicationEvent>,
    #[behaviour(ignore)]
    response_channels: BTreeMap<ReqId, ResponseChannel<Response>>,
}

impl P2PNetworkBehaviour {
    /// Creates a new P2PNetworkbehaviour that defines the communication with the libp2p swarm.
    /// It combines the following protocols from libp2p:
    /// - mDNS for peer discovery within the local network
    /// - RequestResponse Protocol for sending request and Response messages. This stronghold-communication library
    ///   defines a custom version of this protocol that for sending pings, string-messages and key-value-records.
    ///
    /// # Example
    /// ```no_run
    /// use communication::{
    ///     behaviour::P2PNetworkBehaviour,
    ///     error::QueryResult,
    ///     message::{Request, Response},
    /// };
    /// use libp2p::{
    ///     core::{Multiaddr, PeerId},
    ///     identity::Keypair,
    ///     request_response::{RequestId, RequestResponseEvent, ResponseChannel},
    /// };
    ///
    /// let local_keys = Keypair::generate_ed25519();
    /// let mut swarm = P2PNetworkBehaviour::new(local_keys).unwrap();
    /// ```
    pub fn new(local_keys: Keypair) -> QueryResult<Swarm<P2PNetworkBehaviour>> {
        #[allow(unused_variables)]
        let local_peer_id = PeerId::from(local_keys.public());

        #[cfg(feature = "mdns")]
        let mdns =
            Mdns::new().map_err(|_| QueryError::ConnectionError("Could not build mdns behaviour".to_string()))?;

        let identify = Identify::new(
            "/identify/0.1.0".into(),
            "stronghold-communication".into(),
            local_keys.public(),
        );
        // Create RequestResponse behaviour with MessageProtocol
        let msg_proto = {
            let cfg = RequestResponseConfig::default();
            let protocols = iter::once((MessageProtocol(), ProtocolSupport::Full));
            RequestResponse::new(MessageCodec(), protocols, cfg)
        };

        let behaviour = P2PNetworkBehaviour {
            #[cfg(feature = "mdns")]
            mdns,
            msg_proto,
            identify,
            peers: BTreeMap::new(),
            events: Vec::new(),
            response_channels: BTreeMap::new(),
        };
        let transport = build_tcp_ws_noise_mplex_yamux(local_keys)
            .map_err(|_| QueryError::ConnectionError("Could not build transport layer".to_string()))?;
        Ok(Swarm::new(transport, behaviour, local_peer_id))
    }

    fn poll<TEv>(
        &mut self,
        _cx: &mut Context<'_>,
        _params: &mut impl PollParameters,
    ) -> Poll<NetworkBehaviourAction<TEv, CommunicationEvent>> {
        if !self.events.is_empty() {
            return Poll::Ready(NetworkBehaviourAction::GenerateEvent(self.events.remove(0)));
        }
        Poll::Pending
    }

    pub fn start_listening(
        swarm: &mut Swarm<P2PNetworkBehaviour>,
        listening_addr: Option<Multiaddr>,
    ) -> QueryResult<ListenerId> {
        let addr = listening_addr
            .or_else(|| Multiaddr::from_str("/ip4/0.0.0.0/tcp/0").ok())
            .ok_or_else(|| QueryError::ConnectionError("Invalid Multiaddr".to_string()))?;
        Swarm::listen_on(swarm, addr).map_err(|e| QueryError::ConnectionError(format!("{}", e)))
    }

    pub fn add_peer(&mut self, peer_id: PeerId, addr: Multiaddr) {
        self.peers.insert(peer_id.to_string(), addr);
    }

    pub fn get_peer_addr(&self, peer_id: PeerId) -> Option<&Multiaddr> {
        self.peers.get(&peer_id.to_string())
    }

    pub fn get_all_peers(&self) -> &BTreeMap<String, Multiaddr> {
        &self.peers
    }

    pub fn send_request(&mut self, peer_id: PeerId, request: Request) -> RequestId {
        self.msg_proto.send_request(&peer_id, request)
    }

    pub fn send_response(&mut self, response: Response, request_id: RequestId) -> QueryResult<()> {
        let channel = self
            .response_channels
            .remove(&request_id.to_string())
            .ok_or_else(|| QueryError::MissingChannelError(request_id.to_string()))?;
        self.msg_proto.send_response(channel, response);
        Ok(())
    }
    #[cfg(feature = "mdns")]
    /// Get the peers discovered by mdns
    pub fn get_active_mdns_peers(&mut self) -> Vec<&PeerId> {
        self.mdns.discovered_nodes().collect()
    }
}

#[cfg(feature = "mdns")]
impl NetworkBehaviourEventProcess<MdnsEvent> for P2PNetworkBehaviour {
    // Called when `mdns` produces an event.
    #[allow(unused_variables)]
    fn inject_event(&mut self, event: MdnsEvent) {
        if let MdnsEvent::Discovered(list) = event {
            for (peer_id, multiaddr) in list {
                self.add_peer(peer_id, multiaddr);
            }
        }
    }
}

impl NetworkBehaviourEventProcess<RequestResponseEvent<Request, Response>> for P2PNetworkBehaviour {
    // Called when the protocol produces an event.
    fn inject_event(&mut self, event: RequestResponseEvent<Request, Response>) {
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
            self.response_channels.insert(request_id.to_string(), channel);
            CommunicationEvent::RequestResponse {
                peer_id: peer,
                request_id,
                event: ReqResEvent::Req(request),
            }
        } else {
            CommunicationEvent::from(event)
        };
        self.events.push(communication_event);
    }
}

impl NetworkBehaviourEventProcess<IdentifyEvent> for P2PNetworkBehaviour {
    // Called when `identify` produces an event.
    fn inject_event(&mut self, event: IdentifyEvent) {
        self.events.push(CommunicationEvent::from(event));
    }
}

#[cfg(test)]
fn mock_swarm() -> Swarm<P2PNetworkBehaviour> {
    let local_keys = Keypair::generate_ed25519();
    P2PNetworkBehaviour::new(local_keys).unwrap()
}

#[cfg(test)]
fn mock_addr() -> Multiaddr {
    Multiaddr::from_str("/ip4/127.0.0.1/tcp/0").unwrap()
}

#[test]
fn test_new_behaviour() {
    let local_keys = Keypair::generate_ed25519();
    let swarm = P2PNetworkBehaviour::new(local_keys.clone()).unwrap();
    assert_eq!(
        &PeerId::from_public_key(local_keys.public()),
        Swarm::local_peer_id(&swarm)
    );
    assert!(swarm.get_all_peers().is_empty());
}

#[test]
fn test_add_peer() {
    let mut swarm = mock_swarm();
    let peer_id = PeerId::random();
    swarm.add_peer(peer_id.clone(), mock_addr());
    assert!(swarm.get_peer_addr(peer_id.clone()).is_some());
    assert!(swarm.get_all_peers().contains_key(&peer_id.to_string()));
}
