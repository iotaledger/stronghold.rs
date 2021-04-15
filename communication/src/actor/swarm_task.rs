// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::{connections::ConnectionManager, *};
use crate::behaviour::{
    BehaviourError, MessageEvent, P2PEvent, P2PNetworkBehaviour, P2POutboundFailure, P2PReqResEvent,
};
use core::{ops::Deref, time::Duration};
use futures::{channel::mpsc::UnboundedReceiver, future, prelude::*, select};
use libp2p::{
    core::{connection::ListenerId, multiaddr::Protocol, ConnectedPoint, Multiaddr, PeerId},
    identity::Keypair,
    request_response::RequestId,
    swarm::{IntoProtocolsHandler, NetworkBehaviour, ProtocolsHandler, Swarm, SwarmEvent},
};
use riker::{actors::*, Message};
use std::{
    collections::HashMap,
    net::Ipv4Addr,
    task::{Context, Poll},
    time::Instant,
};

type HandleErr<Req, Res> =  <<<P2PNetworkBehaviour<Req, Res> as NetworkBehaviour>::ProtocolsHandler as IntoProtocolsHandler>::Handler as ProtocolsHandler>::Error;
type P2PSwarmEvent<Req, Res> = SwarmEvent<P2PEvent<Req, Res>, HandleErr<Req, Res>>;

// Separate task that manages the swarm communication.
pub(super) struct SwarmTask<Req, Res, ClientMsg, P>
where
    Req: MessageEvent + ToPermissionVariants<P> + Into<ClientMsg>,
    Res: MessageEvent,
    ClientMsg: Message,
    P: Message + VariantPermission,
{
    system: ActorSystem,
    // client to receive incoming requests
    client: ActorRef<ClientMsg>,
    // firewall configuration to check and validate all outgoing and incoming requests
    firewall: FirewallConfiguration,
    // the expanded swarm that is used to poll for incoming requests and interact
    swarm: Swarm<P2PNetworkBehaviour<Req, Res>>,
    // channel from the communication actor to this task
    swarm_rx: UnboundedReceiver<(CommunicationRequest<Req, ClientMsg>, Sender)>,
    // Listener in the local swarm
    listener: Option<(ListenerId, Multiaddr)>,
    // relays that are tried if a peer can not be reached directly
    dialing_relays: Vec<PeerId>,
    // relays that are used for listening
    listening_relays: HashMap<PeerId, ListenerId>,
    // relay addresses
    relay_addr: HashMap<PeerId, Multiaddr>,
    // maintain the current state of connections and keep-alive configuration
    connection_manager: ConnectionManager,
    _marker: PhantomData<P>,
}

impl<Req, Res, ClientMsg, P> SwarmTask<Req, Res, ClientMsg, P>
where
    Req: MessageEvent + ToPermissionVariants<P> + Into<ClientMsg>,
    Res: MessageEvent,
    ClientMsg: Message,
    P: Message + VariantPermission,
{
    pub async fn new(
        system: ActorSystem,
        swarm_rx: UnboundedReceiver<(CommunicationRequest<Req, ClientMsg>, Sender)>,
        actor_config: CommunicationActorConfig<ClientMsg>,
        keypair: Keypair,
        behaviour: BehaviourConfig,
    ) -> Result<Self, BehaviourError> {
        // Create a P2PNetworkBehaviour for the swarm communication.
        let swarm = P2PNetworkBehaviour::<Req, Res>::init_swarm(keypair, behaviour).await?;
        let firewall = FirewallConfiguration::new(actor_config.firewall_default_in, actor_config.firewall_default_out);
        Ok(SwarmTask {
            system,
            client: actor_config.client,
            firewall,
            swarm,
            swarm_rx,
            listener: None,
            dialing_relays: Vec::new(),
            listening_relays: HashMap::new(),
            relay_addr: HashMap::new(),
            connection_manager: ConnectionManager::new(),
            _marker: PhantomData,
        })
    }

    // Poll from the swarm for events from remote peers, and from the `swarm_tx` channel for events from the local
    // actor, and forward them.
    pub async fn poll_swarm(mut self) {
        loop {
            select! {
                swarm_event = self.swarm.next_event().fuse() => self.handle_swarm_event(swarm_event),
                actor_event = self.swarm_rx.next().fuse() => {
                    if let Some((message, sender)) = actor_event {
                        if let CommunicationRequest::Shutdown = message {
                            break;
                        } else {
                            self.handle_actor_request(message, sender)
                        }
                    } else {
                        break
                    }
                },
            };
        }
        self.shutdown();
    }

    fn shutdown(mut self) {
        if let Some((listener_id, _)) = self.listener.take() {
            let _ = self.swarm.remove_listener(listener_id);
        }
        self.swarm_rx.close();
    }

    // Send a response to the sender of a previous CommunicationRequest
    fn send_response(result: CommunicationResults<Res>, sender: Sender) {
        if let Some(sender) = sender {
            let _ = sender.try_tell(result, None);
        }
    }

    // Poll the swarm, check for each event if the provided function returns a match for it.
    // Return None on timeout.
    fn await_event<T>(
        &mut self,
        timeout: Duration,
        matches: &dyn Fn(&P2PSwarmEvent<Req, Res>) -> Option<T>,
    ) -> Option<T> {
        task::block_on(async {
            let start = Instant::now();
            loop {
                let event = self.swarm.next_event().await;
                let matched = matches(&event);
                if matched.is_some() {
                    return matched;
                }
                self.handle_swarm_event(event);
                if start.elapsed() > timeout {
                    return None;
                }
            }
        })
    }

    // Start listening on the swarm, if not address is provided, the port will be OS assigned.
    fn start_listening(&mut self, addr: Option<Multiaddr>) -> Result<(ListenerId, Multiaddr), ()> {
        let addr = addr.unwrap_or_else(|| {
            Multiaddr::empty()
                .with(Protocol::Ip4(Ipv4Addr::new(0, 0, 0, 0)))
                .with(Protocol::Tcp(0u16))
        });
        let listener_id = self.swarm.listen_on(addr).map_err(|_| ())?;
        let match_event = |event: &SwarmEvent<P2PEvent<Req, Res>, _>| match event {
            SwarmEvent::NewListenAddr(addr) => Some(addr.clone()),
            _ => None,
        };
        let res: Option<Multiaddr> = self.await_event(Duration::from_secs(3), &match_event);
        res.map(|addr| (listener_id, addr)).ok_or(())
    }

    // Stop listening to the swarm.
    fn stop_listening(&mut self, listener: ListenerId, addr: &Multiaddr) -> Result<(), ()> {
        self.swarm.remove_listener(listener)?;
        let match_event = |event: &SwarmEvent<P2PEvent<Req, Res>, _>| match event {
            SwarmEvent::ExpiredListenAddr(address) if address == addr => Some(()),
            SwarmEvent::ListenerClosed { addresses, .. } if addresses.contains(&addr) => Some(()),
            _ => None,
        };
        self.await_event(Duration::from_secs(3), &match_event).ok_or(())
    }

    // Poll for the result of an connection attempt to a remote peer.
    fn await_connect_result(
        &mut self,
        target_peer: &PeerId,
        target_addr: &Option<Multiaddr>,
    ) -> Result<ConnectedPoint, ConnectPeerError> {
        let match_event = |event: &SwarmEvent<P2PEvent<Req, Res>, _>| match event {
            SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } if peer_id == target_peer => {
                Some(Ok(endpoint.clone()))
            }
            SwarmEvent::UnreachableAddr {
                peer_id,
                error,
                attempts_remaining: 0,
                ..
            } if peer_id == target_peer => Some(Err(ConnectPeerError::from(error))),
            SwarmEvent::UnknownPeerUnreachableAddr { address, error } if Some(address) == target_addr.as_ref() => {
                Some(Err(ConnectPeerError::from(error)))
            }
            _ => None,
        };
        let res = self.await_event(Duration::from_secs(3), &match_event);
        res.unwrap_or(Err(ConnectPeerError::Timeout))
    }

    // Try to connect a remote peer by address.
    fn connect_peer_via_addr(
        &mut self,
        target_peer: &PeerId,
        target_addr: Multiaddr,
    ) -> Result<ConnectedPoint, ConnectPeerError> {
        self.swarm.dial_addr(target_addr.clone())?;
        self.await_connect_result(target_peer, &Some(target_addr))
    }

    // Try to connect a remote peer by id.
    // This may be successful if the address was formerly known or e.g. discovered via mDNS.
    fn connect_peer(&mut self, target_peer: &PeerId) -> Result<ConnectedPoint, ConnectPeerError> {
        self.swarm.dial(target_peer)?;
        self.await_connect_result(target_peer, &None)
    }

    // Add a new peer with it's address. If the peer can not be dialed directly and is not a relay, try to reach it via
    // one of the relay_addr.
    fn add_peer(
        &mut self,
        target_peer: PeerId,
        target_addr: Option<Multiaddr>,
        is_relay: Option<RelayDirection>,
    ) -> Result<PeerId, ConnectPeerError> {
        let target_addr = target_addr.or_else(|| is_relay.as_ref().and(self.relay_addr.get(&target_peer).cloned()));
        let mut res = match target_addr {
            Some(addr) => self.connect_peer_via_addr(&target_peer, addr),
            None => self.connect_peer(&target_peer),
        };

        let is_eligible_to_try_relayed = match res {
            Err(ConnectPeerError::NoAddresses)
            | Err(ConnectPeerError::Transport)
            | Err(ConnectPeerError::Timeout)
            | Err(ConnectPeerError::InvalidAddress(_)) => is_relay.is_none(),
            _ => false,
        };

        if is_eligible_to_try_relayed {
            let dialing_relays = self.dialing_relays.clone();
            let try_relayed = dialing_relays.iter().find_map(|relay| {
                let addr = self.relay_addr.get(&relay)?;
                let relayed_addr = addr
                    .clone()
                    .with(Protocol::P2p(relay.clone().into()))
                    .with(Protocol::P2pCircuit)
                    .with(Protocol::P2p(target_peer.into()));
                self.connect_peer_via_addr(&target_peer, relayed_addr).map(Ok).ok()
            });
            res = try_relayed.unwrap_or(res);
        }

        res.and_then(|connected_point| {
            if let Some(direction) = is_relay {
                self.relay_addr
                    .insert(target_peer, connected_point.get_remote_address().clone());
                self.connection_manager
                    .insert(target_peer, connected_point, Some(direction.clone()));
                self.set_relay(target_peer, direction)
            } else {
                self.connection_manager.insert(target_peer, connected_point, None);
                Ok(target_peer)
            }
        })
    }

    // Try sending a request to a remote peer if it was approved by the firewall, and return the received
    // Response. If no response is received, a timeout error will be returned.
    fn send_request(&mut self, peer_id: PeerId, req: Req) -> Result<Res, RequestMessageError> {
        let req_id = self.swarm.behaviour_mut().send_request(&peer_id, req);
        let match_event = |event: &SwarmEvent<P2PEvent<Req, Res>, _>| match event {
            SwarmEvent::Behaviour(P2PEvent::RequestResponse(boxed)) => match boxed.deref().clone() {
                P2PReqResEvent::Res {
                    request_id, response, ..
                } if request_id == req_id => Some(Ok(response)),
                P2PReqResEvent::InboundFailure { request_id, error, .. } if request_id == req_id => {
                    Some(Err(RequestMessageError::Inbound(error)))
                }
                P2PReqResEvent::OutboundFailure { request_id, error, .. } if request_id == req_id => {
                    Some(Err(RequestMessageError::Outbound(error)))
                }
                _ => None,
            },
            _ => None,
        };
        let res: Option<Result<Res, RequestMessageError>> = self.await_event(Duration::from_secs(3), &match_event);
        res.unwrap_or(Err(RequestMessageError::Outbound(P2POutboundFailure::Timeout)))
    }

    #[allow(clippy::map_entry)]
    // Add a relay for listening if it is not already known.
    // This will start listening on the relayed address and attempt to connect to the relay, if it is not connected yet.
    fn add_listener_relay(&mut self, relay_id: PeerId) -> Result<PeerId, ConnectPeerError> {
        if !self.listening_relays.contains_key(&relay_id) {
            let local_id = *self.swarm.local_peer_id();
            let relay_addr = self.relay_addr.get(&relay_id).ok_or(ConnectPeerError::NoAddresses)?;
            let addr = relay_addr
                .clone()
                .with(Protocol::P2p(relay_id.into()))
                .with(Protocol::P2pCircuit)
                .with(Protocol::P2p(local_id.into()));
            let (listener_id, _) = self
                .start_listening(Some(addr.clone()))
                .map_err(|()| ConnectPeerError::Io)?;
            if !self.swarm.is_connected(&relay_id) {
                self.await_connect_result(&relay_id, &Some(addr))?;
            }
            self.listening_relays.insert(relay_id, listener_id);
        }
        Ok(relay_id)
    }

    // Set the new relay configuration to use the relay for dialing, listening or both.
    fn set_relay(&mut self, peer_id: PeerId, direction: RelayDirection) -> Result<PeerId, ConnectPeerError> {
        match direction {
            RelayDirection::Dialing => {
                if let Some(listener) = self.listening_relays.remove(&peer_id) {
                    let _ = match self.relay_addr.get(&peer_id).cloned() {
                        Some(addr) => self.stop_listening(listener, &addr),
                        None => self.swarm.remove_listener(listener),
                    };
                }
                if !self.dialing_relays.contains(&peer_id) {
                    self.dialing_relays.push(peer_id);
                }
                Ok(peer_id)
            }
            RelayDirection::Listening => {
                self.dialing_relays.retain(|p| *p == peer_id);
                self.add_listener_relay(peer_id)
            }
            RelayDirection::Both => {
                if !self.dialing_relays.contains(&peer_id) {
                    self.dialing_relays.push(peer_id);
                }
                self.add_listener_relay(peer_id)
            }
        }
    }

    // Remove relay from listeners and dialing relays.
    // Keep the address in case that the relay will be used in the future again.
    fn remove_relay(&mut self, relay_id: &PeerId) {
        if let Some(listener) = self.listening_relays.remove(relay_id) {
            let _ = self.swarm.remove_listener(listener);
        }
        self.dialing_relays.retain(|r| r == relay_id);
    }

    // Change or add rules to adjust the permissions specific peers or the default rule.
    // If a permission is added / removed for a peer that has no rule yet, a new rule will be added
    // for that peer based on the default rule with changed permissions.
    fn update_firewall_rule(
        &mut self,
        peers: Vec<PeerId>,
        direction: &RequestDirection,
        permissions: Vec<PermissionValue>,
        is_add: bool,
        is_change_default: bool,
    ) {
        let default = self.firewall.get_default(direction);
        let (have_rule, no_rule) = peers
            .into_iter()
            .partition::<Vec<PeerId>, _>(|p| self.firewall.has_rule(&p, direction));

        if !no_rule.is_empty() || is_change_default {
            let updated_default = is_add
                .then(|| default.add_permissions(&permissions))
                .unwrap_or_else(|| default.remove_permissions(&permissions));
            no_rule
                .into_iter()
                .for_each(|peer| self.firewall.set_rule(peer, direction, updated_default));
            is_change_default.then(|| self.firewall.set_default(&direction, updated_default));
        }

        have_rule.into_iter().for_each(|peer| {
            if let Some(rule) = self.firewall.get_rule(&peer, direction) {
                let update = is_add
                    .then(|| rule.add_permissions(&permissions))
                    .unwrap_or_else(|| rule.remove_permissions(&permissions));
                self.firewall.set_rule(peer, direction, update)
            };
        })
    }

    // Configure the firewall by either adding, changing, overwriting, or removing rules.
    fn configure_firewall(&mut self, rule: FirewallRule) {
        match rule {
            FirewallRule::SetRules {
                direction,
                peers,
                set_default,
                permission,
            } => {
                for peer in peers {
                    self.firewall.set_rule(peer, &direction, permission);
                }
                if set_default {
                    self.firewall.set_default(&direction, permission);
                }
            }
            FirewallRule::AddPermissions {
                direction,
                peers,
                change_default,
                permissions,
            } => {
                self.update_firewall_rule(peers, &direction, permissions, true, change_default);
            }
            FirewallRule::RemovePermissions {
                direction,
                peers,
                change_default,
                permissions,
            } => {
                self.update_firewall_rule(peers, &direction, permissions, false, change_default);
            }
            FirewallRule::RemoveRule { peers, direction } => {
                for peer in peers {
                    self.firewall.remove_rule(&peer, &direction);
                }
            }
        }
    }

    // Handle the messages that are received from other actors in the system.
    fn handle_actor_request(&mut self, event: CommunicationRequest<Req, ClientMsg>, sender: Sender) {
        match event {
            CommunicationRequest::SetClientRef(client_ref) => {
                self.client = client_ref;
                let res = CommunicationResults::SetClientRefAck;
                Self::send_response(res, sender);
            }
            CommunicationRequest::StartListening(addr) => {
                let res = self
                    .listener
                    .is_none()
                    .then(|| {
                        self.start_listening(addr).map(|(listener, addr)| {
                            self.listener = Some((listener, addr.clone()));
                            addr
                        })
                    })
                    .unwrap_or(Err(()));
                Self::send_response(CommunicationResults::StartListeningResult(res), sender);
            }
            CommunicationRequest::RemoveListener => {
                if let Some((listener, addr)) = self.listener.take() {
                    let _ = self.stop_listening(listener, &addr);
                }
                Self::send_response(CommunicationResults::RemoveListenerAck, sender);
            }
            CommunicationRequest::AddPeer {
                peer_id,
                addr,
                is_relay,
            } => {
                let res = self.add_peer(peer_id, addr, is_relay);
                Self::send_response(CommunicationResults::AddPeerResult(res), sender);
            }
            CommunicationRequest::RequestMsg { peer_id, request } => {
                let res = self
                    .firewall
                    .is_permitted(&request, &peer_id, RequestDirection::Out)
                    .then(|| self.send_request(peer_id, request))
                    .unwrap_or(Err(RequestMessageError::LocalFirewallRejected));
                Self::send_response(CommunicationResults::RequestMsgResult(res), sender);
            }
            CommunicationRequest::GetSwarmInfo => {
                let peer_id = *self.swarm.local_peer_id();
                let listeners = self.swarm.listeners().cloned().collect();
                let connections = self.connection_manager.current_connections();
                let res = CommunicationResults::SwarmInfo {
                    peer_id,
                    listeners,
                    connections,
                };
                Self::send_response(res, sender);
            }
            CommunicationRequest::BanPeer(peer_id) => {
                self.swarm.ban_peer_id(peer_id);
                let res = CommunicationResults::BannedPeerAck(peer_id);
                Self::send_response(res, sender);
            }
            CommunicationRequest::UnbanPeer(peer_id) => {
                self.swarm.unban_peer_id(peer_id);
                let res = CommunicationResults::UnbannedPeerAck(peer_id);
                Self::send_response(res, sender);
            }
            CommunicationRequest::ConfigRelay { peer_id, direction } => {
                let res = self.set_relay(peer_id, direction);
                Self::send_response(CommunicationResults::ConfigRelayResult(res), sender);
            }
            CommunicationRequest::RemoveRelay(relay_id) => {
                self.remove_relay(&relay_id);
                Self::send_response(CommunicationResults::RemoveRelayAck, sender);
            }
            CommunicationRequest::ConfigureFirewall(rule) => {
                self.configure_firewall(rule);
                Self::send_response(CommunicationResults::ConfigureFirewallAck, sender);
            }
            CommunicationRequest::Shutdown => unreachable!(),
        }
    }

    // Forward request to client actor and wait for the result, with 3s timeout.
    fn ask_client(&mut self, request: Req) -> Option<Res> {
        let start = Instant::now();
        let mut ask_client = ask(&self.system, &self.client, request);
        task::block_on(future::poll_fn(move |cx: &mut Context<'_>| {
            if let Poll::Ready(res) = ask_client.poll_unpin(cx) {
                Poll::Ready(Some(res))
            } else if start.elapsed() > Duration::new(3, 0) {
                Poll::Ready(None)
            } else {
                Poll::Pending
            }
        }))
    }

    // Handle incoming enveloped from either a peer directly or via the relay peer.
    fn handle_incoming_request(&mut self, peer_id: &PeerId, request_id: &RequestId, request: Req) {
        let is_permitted = self.firewall.is_permitted(&request, &peer_id, RequestDirection::In);
        if is_permitted {
            if let Some(res) = self.ask_client(request) {
                let _ = self.swarm.behaviour_mut().send_response(&request_id, res);
            }
        }
    }

    // Send incoming request to the client.
    // Eventually other swarm events lik e.g. incoming connection should also be send to some top level actor.
    fn handle_swarm_event(&mut self, event: SwarmEvent<P2PEvent<Req, Res>, HandleErr<Req, Res>>) {
        match event {
            SwarmEvent::Behaviour(P2PEvent::RequestResponse(boxed_event)) => {
                if let P2PReqResEvent::Req {
                    peer_id,
                    request_id,
                    request,
                } = *boxed_event
                {
                    self.handle_incoming_request(&peer_id, &request_id, request)
                }
            }
            SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                self.connection_manager.insert(peer_id, endpoint, None);
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established: 0,
                ..
            } => {
                if !self.listening_relays.contains_key(&peer_id) || self.connect_peer(&peer_id).is_err() {
                    self.remove_relay(&peer_id);
                    self.connection_manager.remove_connection(&peer_id);
                }
            }
            _ => {}
        }
    }
}
