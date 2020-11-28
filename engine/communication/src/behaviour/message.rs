// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use libp2p::{
    core::{Multiaddr, PeerId},
    identify::IdentifyEvent,
    identity::PublicKey,
    request_response::{InboundFailure, OutboundFailure, RequestId, RequestResponseEvent, RequestResponseMessage},
    swarm::ProtocolsHandlerUpgrErr,
};
use serde::{Deserialize, Serialize};

#[cfg(feature = "mdns")]
use libp2p::mdns::MdnsEvent;

/// Event that can be produced by the `Mdns` behaviour.
#[derive(Debug, Clone)]
pub enum P2PMdnsEvent {
    /// Discovered nodes through mDNS.
    Discovered(Vec<(PeerId, Multiaddr)>),
    /// Each discovered record has a time-to-live. When this TTL expires and the address hasn't
    /// been refreshed, it is removed from the list and emit it as an `Expired` event.
    Expired(Vec<(PeerId, Multiaddr)>),
}

/// Information of a peer sent in `Identify` protocol responses.
#[derive(Debug, Clone)]
pub struct P2PIdentifyInfo {
    /// The public key underlying the peer's `PeerId`.
    pub public_key: PublicKey,
    /// Version of the protocol family used by the peer, e.g. `ipfs/1.0.0`
    pub protocol_version: String,
    /// Name and version of the peer, similar to the `User-Agent` header in
    /// the HTTP protocol.
    pub agent_version: String,
    /// The addresses that the peer is listening on.
    pub listen_addrs: Vec<Multiaddr>,
    /// The list of protocols supported by the peer, e.g. `/ipfs/ping/1.0.0`.
    pub protocols: Vec<String>,
}

/// Error that can happen on an outbound substream opening attempt.
#[derive(Debug, Clone)]
pub enum P2PProtocolsHandlerUpgrErr {
    /// The opening attempt timed out before the negotiation was fully completed.
    Timeout,
    /// There was an error in the timer used.
    Timer,
    /// Error while upgrading the substream to the protocol we want.
    Upgrade,
}

/// Event emitted  by the `Identify` behaviour.
#[derive(Debug, Clone)]
pub enum P2PIdentifyEvent {
    /// Identifying information has been received from a peer.
    Received {
        info: P2PIdentifyInfo,
        /// The address observed by the peer for the local node.
        observed_addr: Multiaddr,
    },
    /// Identifying information of the local node has been sent to a peer.
    Sent,
    /// Error while attempting to identify the remote.
    Error(P2PProtocolsHandlerUpgrErr),
}
/// Possible failures occurring in the context of sending
/// an outbound request and receiving the response.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum P2POutboundFailure {
    /// The request could not be sent because a dialing attempt failed.
    DialFailure,
    /// The request timed out before a response was received.
    ///
    /// It is not known whether the request may have been
    /// received (and processed) by the remote peer.
    Timeout,
    /// The connection closed before a response was received.
    ///
    /// It is not known whether the request may have been
    /// received (and processed) by the remote peer.
    ConnectionClosed,
    /// The remote supports none of the requested protocols.
    UnsupportedProtocols,
}

/// Possible failures occurring in the context of receiving an
/// inbound request and sending a response.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum P2PInboundFailure {
    /// The inbound request timed out, either while reading the
    /// incoming request or before a response is sent
    Timeout,
    /// The local peer supports none of the requested protocols.
    UnsupportedProtocols,
    /// The connection closed before a response was delivered.
    ConnectionClosed,
}

/// Event emitted  by the `RequestResponse` behaviour.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum P2PReqResEvent<T, U> {
    /// Request Message
    ///
    /// Requests require a response to acknowledge them, if [`P2PNetworkBehaviour::send_response`]
    /// is not called in a timely manner, the protocol issues an
    /// `InboundFailure` at the local node and an `OutboundFailure` at the remote.
    Req(T),
    /// Response Message to a received `Req`.
    ///
    /// The `ResponseChannel` for the request is stored by the `P2PNetwokBehaviour` in
    /// a Hashmap and identified by the  `request_id` that can be used to send the response.
    /// If the `ResponseChannel` for the `request_id`is already closed
    /// due to a timeout, the response is discarded and eventually
    /// [`RequestResponseEvent::InboundFailure`] is emitted.
    Res(U),
    InboundFailure(P2PInboundFailure),
    OutboundFailure(P2POutboundFailure),
}

/// Event that was emitted by one of the protocols of the `P2PNetwokBehaviour`
#[derive(Debug, Clone)]
pub enum CommunicationEvent<T, U> {
    Mdns(P2PMdnsEvent),
    Identify {
        peer_id: PeerId,
        event: P2PIdentifyEvent,
    },
    RequestResponse {
        peer_id: PeerId,
        request_id: RequestId,
        event: P2PReqResEvent<T, U>,
    },
}

#[cfg(feature = "mdns")]
impl<T, U> From<MdnsEvent> for CommunicationEvent<T, U> {
    fn from(event: MdnsEvent) -> CommunicationEvent<T, U> {
        match event {
            MdnsEvent::Discovered(list) => CommunicationEvent::Mdns(P2PMdnsEvent::Discovered(list.collect())),
            MdnsEvent::Expired(list) => CommunicationEvent::Mdns(P2PMdnsEvent::Expired(list.collect())),
        }
    }
}

impl<T, U> From<IdentifyEvent> for CommunicationEvent<T, U> {
    fn from(event: IdentifyEvent) -> CommunicationEvent<T, U> {
        match event {
            IdentifyEvent::Received {
                peer_id,
                info,
                observed_addr,
            } => CommunicationEvent::Identify {
                peer_id,
                event: P2PIdentifyEvent::Received {
                    info: P2PIdentifyInfo {
                        public_key: info.public_key,
                        protocol_version: info.protocol_version,
                        agent_version: info.agent_version,
                        listen_addrs: info.listen_addrs,
                        protocols: info.protocols,
                    },
                    observed_addr,
                },
            },
            IdentifyEvent::Sent { peer_id } => CommunicationEvent::Identify {
                peer_id,
                event: P2PIdentifyEvent::Sent,
            },
            IdentifyEvent::Error { peer_id, error } => {
                let err = match error {
                    ProtocolsHandlerUpgrErr::Timeout => P2PProtocolsHandlerUpgrErr::Timeout,
                    ProtocolsHandlerUpgrErr::Timer => P2PProtocolsHandlerUpgrErr::Timer,
                    ProtocolsHandlerUpgrErr::Upgrade(_) => P2PProtocolsHandlerUpgrErr::Upgrade,
                };
                CommunicationEvent::Identify {
                    peer_id,
                    event: P2PIdentifyEvent::Error(err),
                }
            }
        }
    }
}

impl<T, U> From<RequestResponseEvent<T, U>> for CommunicationEvent<T, U> {
    fn from(event: RequestResponseEvent<T, U>) -> CommunicationEvent<T, U> {
        match event {
            RequestResponseEvent::Message { peer, message } => match message {
                RequestResponseMessage::Request {
                    request_id,
                    request,
                    channel: _,
                } => CommunicationEvent::RequestResponse {
                    peer_id: peer,
                    request_id,
                    event: P2PReqResEvent::Req(request),
                },
                RequestResponseMessage::Response { request_id, response } => CommunicationEvent::RequestResponse {
                    peer_id: peer,
                    request_id,
                    event: P2PReqResEvent::Res(response),
                },
            },
            RequestResponseEvent::OutboundFailure {
                peer,
                request_id,
                error,
            } => {
                let err = match error {
                    OutboundFailure::DialFailure => P2POutboundFailure::DialFailure,
                    OutboundFailure::Timeout => P2POutboundFailure::Timeout,
                    OutboundFailure::ConnectionClosed => P2POutboundFailure::ConnectionClosed,
                    OutboundFailure::UnsupportedProtocols => P2POutboundFailure::UnsupportedProtocols,
                };
                CommunicationEvent::RequestResponse {
                    peer_id: peer,
                    request_id,
                    event: P2PReqResEvent::OutboundFailure(err),
                }
            }
            RequestResponseEvent::InboundFailure {
                peer,
                request_id,
                error,
            } => {
                let err = match error {
                    InboundFailure::Timeout => P2PInboundFailure::Timeout,
                    InboundFailure::ConnectionClosed => P2PInboundFailure::ConnectionClosed,
                    InboundFailure::UnsupportedProtocols => P2PInboundFailure::UnsupportedProtocols,
                };
                CommunicationEvent::RequestResponse {
                    peer_id: peer,
                    request_id,
                    event: P2PReqResEvent::InboundFailure(err),
                }
            }
        }
    }
}

#[cfg(test)]
mod test {

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub enum Request {
        Ping,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub enum Response {
        Pong,
    }

    use super::*;
    use libp2p::{identify::IdentifyInfo, identity::Keypair, swarm::ProtocolsHandlerUpgrErr, Multiaddr, PeerId};

    fn random_multi_addr() -> Multiaddr {
        "/ip4/0.0.0.0/tcp/0".parse().unwrap()
    }

    fn rand_peer() -> PeerId {
        PeerId::random()
    }

    fn rand_keys() -> Keypair {
        Keypair::generate_ed25519()
    }

    #[test]
    fn from_identify() {
        let peer_id = rand_peer();
        let received_event = IdentifyEvent::Received {
            peer_id: peer_id.clone(),
            observed_addr: random_multi_addr(),
            info: IdentifyInfo {
                public_key: rand_keys().public(),
                protocol_version: "0".to_string(),
                agent_version: "o".to_string(),
                listen_addrs: [].to_vec(),
                protocols: [].to_vec(),
            },
        };
        let sent_event = IdentifyEvent::Sent {
            peer_id: peer_id.clone(),
        };
        let error_event = IdentifyEvent::Error {
            peer_id: peer_id.clone(),
            error: ProtocolsHandlerUpgrErr::Timeout,
        };
        let events = vec![received_event, sent_event, error_event];
        for event in events {
            let _comm_event = CommunicationEvent::<Request, Response>::from(event);
            //             let expected_comm_event = CommunicationEvent::Identify(event);
            //             assert_eq!(comm_event, expected_comm_event);
        }
    }
}
