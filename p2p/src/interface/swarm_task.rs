// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    assemble_relayed_addr,
    behaviour::{BehaviourState, EstablishedConnections},
    firewall::{FirewallRules, FwRequest},
    RelayNotSupported,
};
use futures::{
    channel::{mpsc, oneshot},
    prelude::*,
};
use libp2p::{
    swarm::{NetworkBehaviour, Swarm, SwarmEvent},
    Multiaddr, PeerId,
};
use smallvec::SmallVec;
use std::{collections::HashMap, convert::TryFrom};

use super::{errors::*, types::*, BehaviourEvent, EventChannel, ListenerId, NetBehaviour, Rule, RuleDirection};

pub type Ack = ();

// Perform actions on the Swarm.
// The return value is sent back through the `tx_yield` oneshot channel.
pub enum SwarmOperation<Rq, Rs, TRq> {
    SendRequest {
        peer: PeerId,
        request: Rq,
        tx_yield: oneshot::Sender<Result<Rs, OutboundFailure>>,
    },

    ConnectPeer {
        peer: PeerId,
        tx_yield: oneshot::Sender<Result<Multiaddr, DialErr>>,
    },
    GetIsConnected {
        peer: PeerId,
        tx_yield: oneshot::Sender<bool>,
    },
    GetConnections {
        tx_yield: oneshot::Sender<Vec<(PeerId, EstablishedConnections)>>,
    },

    StartListening {
        address: Multiaddr,
        tx_yield: oneshot::Sender<Result<Multiaddr, ListenErr>>,
    },
    StartRelayedListening {
        relay: PeerId,
        relay_addr: Option<Multiaddr>,
        tx_yield: oneshot::Sender<Result<Multiaddr, ListenRelayErr>>,
    },
    GetListeners {
        tx_yield: oneshot::Sender<Vec<Listener>>,
    },
    StopListening {
        tx_yield: oneshot::Sender<Ack>,
    },
    StopListeningAddr {
        address: Multiaddr,
        tx_yield: oneshot::Sender<Ack>,
    },
    StopListeningRelay {
        relay: PeerId,
        tx_yield: oneshot::Sender<bool>,
    },

    GetPeerAddrs {
        peer: PeerId,
        tx_yield: oneshot::Sender<Vec<Multiaddr>>,
    },
    AddPeerAddr {
        peer: PeerId,
        address: Multiaddr,
        tx_yield: oneshot::Sender<Ack>,
    },
    RemovePeerAddr {
        peer: PeerId,
        address: Multiaddr,
        tx_yield: oneshot::Sender<Ack>,
    },

    AddDialingRelay {
        peer: PeerId,
        address: Option<Multiaddr>,
        tx_yield: oneshot::Sender<Result<Option<Multiaddr>, RelayNotSupported>>,
    },
    RemoveDialingRelay {
        peer: PeerId,
        tx_yield: oneshot::Sender<bool>,
    },
    SetRelayFallback {
        peer: PeerId,
        use_relay_fallback: bool,
        tx_yield: oneshot::Sender<Result<(), RelayNotSupported>>,
    },
    UseSpecificRelay {
        target: PeerId,
        relay: PeerId,
        is_exclusive: bool,
        tx_yield: oneshot::Sender<Result<Option<Multiaddr>, RelayNotSupported>>,
    },

    GetFirewallDefault {
        tx_yield: oneshot::Sender<FirewallRules<TRq>>,
    },
    SetFirewallDefault {
        direction: RuleDirection,
        default: Rule<TRq>,
        tx_yield: oneshot::Sender<Ack>,
    },
    RemoveFirewallDefault {
        direction: RuleDirection,
        tx_yield: oneshot::Sender<Ack>,
    },
    GetPeerRules {
        peer: PeerId,
        tx_yield: oneshot::Sender<FirewallRules<TRq>>,
    },
    SetPeerRule {
        peer: PeerId,
        direction: RuleDirection,
        rule: Rule<TRq>,
        tx_yield: oneshot::Sender<Ack>,
    },
    RemovePeerRule {
        peer: PeerId,
        direction: RuleDirection,
        tx_yield: oneshot::Sender<Ack>,
    },

    BanPeer {
        peer: PeerId,
        tx_yield: oneshot::Sender<Ack>,
    },
    UnbanPeer {
        peer: PeerId,
        tx_yield: oneshot::Sender<Ack>,
    },

    ExportConfig {
        tx_yield: oneshot::Sender<BehaviourState<TRq>>,
    },
}

// Central task that is responsible for all Swarm interaction.
// Drives the [`Swarm`] by continuously polling for the next [`SwarmEvent`].
//
// Operations on the Swarm are performed based on the [`SwarmOperation`]s that are received through the `command_rx`
// channel. The outcome for each operation is returned through the oneshot channel that is included in the
// [`SwarmOperation`]. No operation is blocking, instead the return-channel is cached until an outcome yields.
pub struct SwarmTask<Rq, Rs, TRq>
where
    Rq: RqRsMessage,
    Rs: RqRsMessage,
    TRq: FwRequest<Rq>,
{
    // libp2p [`Swarm`][libp2p::Swarm] that uses `NetBehaviour` as network behaviour protocol.
    swarm: Swarm<NetBehaviour<Rq, Rs, TRq>>,

    // Channel for to receiving [`SwarmOperation`].
    // This will trigger and according action on the Swarm.
    // The result of an operation is send via the oneshot Sender that is included in each type.
    command_rx: mpsc::Receiver<SwarmOperation<Rq, Rs, TRq>>,

    // Channel for forwarding inbound requests.
    // [`ReceiveRequest`] includes a oneshot Sender for returning a response.
    request_channel: EventChannel<ReceiveRequest<Rq, Rs>>,
    // Optional channel for forwarding all events on the swarm on listeners and connections.
    event_channel: Option<EventChannel<NetworkEvent>>,

    // Currently active listeners.
    listeners: HashMap<ListenerId, Listener>,

    // Response channels for sent outbound requests.
    // The channels are cached until a response was received or [`OutboundFailure`] occurred.
    await_response: HashMap<RequestId, oneshot::Sender<Result<Rs, OutboundFailure>>>,
    // Response channels for the connection attempts to a remote peer.
    // A result if returned once the remote connected or the dial attempt failed.
    await_connection: HashMap<PeerId, oneshot::Sender<Result<Multiaddr, DialErr>>>,
    // Response channels for start-listening on the transport.
    // A result is returned once the associated listener reported it's first new listening address or a listener error
    // occurred.
    await_listen: HashMap<ListenerId, oneshot::Sender<Result<Multiaddr, ListenErr>>>,
    // Response channels for start-listening via a relay.
    // A result is returned once the associated listener reported it's first new listening address, or a listener error
    // occurred. Additionally, an error will be returned if the relay could not be connected.
    await_relayed_listen: HashMap<ListenerId, (PeerId, oneshot::Sender<Result<Multiaddr, ListenRelayErr>>)>,
}

impl<Rq, Rs, TRq> SwarmTask<Rq, Rs, TRq>
where
    Rq: RqRsMessage,
    Rs: RqRsMessage,
    TRq: FwRequest<Rq>,
{
    // Create new instance of a swarm-task.
    pub fn new(
        swarm: Swarm<NetBehaviour<Rq, Rs, TRq>>,
        command_rx: mpsc::Receiver<SwarmOperation<Rq, Rs, TRq>>,
        request_channel: EventChannel<ReceiveRequest<Rq, Rs>>,
        event_channel: Option<EventChannel<NetworkEvent>>,
    ) -> Self {
        SwarmTask {
            swarm,
            command_rx,
            request_channel,
            event_channel,
            listeners: HashMap::new(),
            await_response: HashMap::new(),
            await_connection: HashMap::new(),
            await_listen: HashMap::new(),
            await_relayed_listen: HashMap::new(),
        }
    }

    // Central loop:
    // - Drive the [`Swarm`] by polling it for events.
    // - Poll the commands-channel for [`SwarmOperation`]s that are sent from [`StrongholdP2p`].
    //
    // If all [`StrongholdP2p`] clones are dropped, the command-channel will return `None` and [`SwarmTask`] will shut
    // down.
    pub async fn run(mut self) {
        loop {
            if let Some(event_channel) = self.event_channel.as_mut() {
                futures::select_biased! {
                    // Drive the swarm and handle events
                    event = self.swarm.select_next_some() => self.handle_swarm_event(event).await,
                    // Receive [`SwarmOperation`]s to initiate operations on the [`Swarm`].
                    command = self.command_rx.next().fuse() => {
                        if let Some(c) = command {
                            self.handle_command(c)
                        } else {
                            break;
                        }
                    },
                    // Drive request channel to forward inbound requests.
                    _ = self.request_channel.next().fuse() => {}
                    // Drive events channel to forward network events.
                    _ = event_channel.next().fuse() => {}
                }
            } else {
                futures::select_biased! {
                    event = self.swarm.select_next_some() => self.handle_swarm_event(event).await,
                    command = self.command_rx.next().fuse() => {
                        if let Some(c) = command {
                            self.handle_command(c)
                        } else {
                            break;
                        }
                    },
                    _ = self.request_channel.next().fuse() => {}
                }
            }
        }
        self.shutdown();
    }

    // Check if the swarm events yields a result for a previously initiated operation.
    // Optionally forward a [`NetworkEvent`] for the event.
    async fn handle_swarm_event<THandleErr>(&mut self, event: SwarmEvent<BehaviourEvent<Rq, Rs>, THandleErr>) {
        match event {
            SwarmEvent::Behaviour(BehaviourEvent::ReceivedRequest {
                request_id,
                peer,
                request,
                response_tx,
            }) => {
                let received_rq = ReceiveRequest {
                    request_id,
                    peer,
                    request,
                    response_tx,
                };
                let _ = self.request_channel.send(received_rq).await;
                return;
            }
            SwarmEvent::Behaviour(BehaviourEvent::ReceivedResponse {
                request_id, response, ..
            }) => {
                if let Some(result_tx) = self.await_response.remove(&request_id) {
                    let _ = result_tx.send(Ok(response));
                }
                return;
            }
            SwarmEvent::Behaviour(BehaviourEvent::OutboundFailure {
                request_id, failure, ..
            }) => {
                if let Some(result_tx) = self.await_response.remove(&request_id) {
                    let _ = result_tx.send(Err(failure));
                }
                return;
            }
            SwarmEvent::ConnectionEstablished {
                peer_id, ref endpoint, ..
            } => {
                if let Some(result_tx) = self.await_connection.remove(&peer_id) {
                    let _ = result_tx.send(Ok(endpoint.get_remote_address().clone()));
                }
            }
            SwarmEvent::OutgoingConnectionError { ref peer_id, error } => {
                if let Some(peer) = peer_id {
                    if let Ok(err) = DialErr::try_from(error) {
                        if let Some(result_tx) = self.await_connection.remove(peer) {
                            let _ = result_tx.send(Err(err));
                        }
                    }
                }
                return;
            }
            SwarmEvent::NewListenAddr {
                ref address,
                ref listener_id,
            } => {
                if let Some(listener) = self.listeners.get_mut(listener_id) {
                    listener.addrs.push(address.clone());
                }
                if let Some((_, result_tx)) = self.await_relayed_listen.remove(listener_id) {
                    let _ = result_tx.send(Ok(address.clone()));
                }
                if let Some(result_tx) = self.await_listen.remove(listener_id) {
                    let _ = result_tx.send(Ok(address.clone()));
                }
            }
            SwarmEvent::ListenerClosed { ref listener_id, .. } => {
                self.listeners.remove(listener_id);
            }
            SwarmEvent::ListenerError { ref listener_id, .. } => {
                self.listeners.remove(listener_id);
            }
            SwarmEvent::ExpiredListenAddr {
                ref listener_id,
                ref address,
            } => {
                if let Some(listener) = self.listeners.get_mut(listener_id) {
                    listener.addrs.retain(|a| a != address);
                }
            }
            SwarmEvent::BannedPeer { peer_id, .. } => {
                if let Some(result_tx) = self.await_connection.remove(&peer_id) {
                    let _ = result_tx.send(Err(DialErr::Banned));
                }
            }
            SwarmEvent::Behaviour(BehaviourEvent::InboundFailure { .. })
            | SwarmEvent::Dialing(..)
            | SwarmEvent::ConnectionClosed { .. }
            | SwarmEvent::IncomingConnection { .. }
            | SwarmEvent::IncomingConnectionError { .. } => {}
        }
        if let Some(event_tx) = self.event_channel.as_mut() {
            if let Ok(ev) = NetworkEvent::try_from(event) {
                let _ = event_tx.send(ev).await;
            }
        }
    }

    // Perform an operation on the Swarm / NetBehaviour.
    //
    // Return the outcome with the oneshot `tx_yield` channel.
    // Cache `tx_yield` if the outcome depends on receiving a `SwarmEvent`.
    fn handle_command(&mut self, command: SwarmOperation<Rq, Rs, TRq>) {
        match command {
            SwarmOperation::SendRequest {
                peer,
                request,
                tx_yield,
            } => {
                let request_id = self.swarm.behaviour_mut().send_request(peer, request);
                self.await_response.insert(request_id, tx_yield);
            }
            SwarmOperation::ConnectPeer { peer, tx_yield } => match self.swarm.dial(peer) {
                Ok(_) => {
                    self.await_connection.insert(peer, tx_yield);
                }
                Err(e) => {
                    // Conversion only fails on variant `DialError::DialPeerConditionFalse`,
                    // which is never returned by `Swarm::dial`.
                    let err = DialErr::try_from(e).expect("Conversion can not fail.");
                    let _ = tx_yield.send(Err(err));
                }
            },
            SwarmOperation::GetIsConnected { peer, tx_yield } => {
                let is_connected = self.swarm.is_connected(&peer);
                let _ = tx_yield.send(is_connected);
            }
            SwarmOperation::GetConnections { tx_yield } => {
                let connections = self.swarm.behaviour().get_established_connections();
                let _ = tx_yield.send(connections);
            }
            SwarmOperation::StartListening { address, tx_yield } => self.start_listening(address, tx_yield),
            SwarmOperation::StartRelayedListening {
                relay,
                relay_addr,
                tx_yield,
            } => self.start_relayed_listening(relay, relay_addr, tx_yield),
            SwarmOperation::GetListeners { tx_yield } => {
                let listeners = self.listeners.values().cloned().collect();
                let _ = tx_yield.send(listeners);
            }
            SwarmOperation::StopListening { tx_yield } => {
                self.remove_listener(|_| true);
                let _ = tx_yield.send(());
            }
            SwarmOperation::StopListeningAddr { address, tx_yield } => {
                self.remove_listener(|l: &Listener| l.addrs.contains(&address));
                let _ = tx_yield.send(());
            }
            SwarmOperation::StopListeningRelay { relay, tx_yield } => {
                let had_relay = self.remove_listener(|l: &Listener| l.uses_relay == Some(relay));
                let _ = tx_yield.send(had_relay);
            }
            SwarmOperation::GetPeerAddrs { peer, tx_yield } => {
                let addrs = self.swarm.behaviour_mut().addresses_of_peer(&peer);
                let _ = tx_yield.send(addrs);
            }
            SwarmOperation::AddPeerAddr {
                peer,
                address,
                tx_yield,
            } => {
                self.swarm.behaviour_mut().add_address(peer, address);
                let _ = tx_yield.send(());
            }
            SwarmOperation::RemovePeerAddr {
                peer,
                address,
                tx_yield,
            } => {
                self.swarm.behaviour_mut().remove_address(&peer, &address);
                let _ = tx_yield.send(());
            }
            SwarmOperation::AddDialingRelay {
                peer,
                address,
                tx_yield,
            } => {
                let relayed_addr = self.swarm.behaviour_mut().add_dialing_relay(peer, address);
                let _ = tx_yield.send(relayed_addr);
            }
            SwarmOperation::RemoveDialingRelay { peer, tx_yield } => {
                let was_relay = self.swarm.behaviour_mut().remove_dialing_relay(&peer);
                let _ = tx_yield.send(was_relay);
            }
            SwarmOperation::SetRelayFallback {
                peer,
                use_relay_fallback,
                tx_yield,
            } => {
                let res = self.swarm.behaviour_mut().set_relay_fallback(peer, use_relay_fallback);
                let _ = tx_yield.send(res);
            }
            SwarmOperation::UseSpecificRelay {
                target,
                relay,
                is_exclusive,
                tx_yield,
            } => {
                let relayed_addr = self
                    .swarm
                    .behaviour_mut()
                    .use_specific_relay(target, relay, is_exclusive);
                let _ = tx_yield.send(relayed_addr);
            }
            SwarmOperation::GetFirewallDefault { tx_yield } => {
                let fw_default = self.swarm.behaviour().get_firewall_default().clone();
                let _ = tx_yield.send(fw_default);
            }
            SwarmOperation::SetFirewallDefault {
                direction,
                default,
                tx_yield,
            } => {
                self.swarm.behaviour_mut().set_firewall_default(direction, default);
                let _ = tx_yield.send(());
            }
            SwarmOperation::RemoveFirewallDefault { direction, tx_yield } => {
                self.swarm.behaviour_mut().remove_firewall_default(direction);
                let _ = tx_yield.send(());
            }
            SwarmOperation::GetPeerRules { peer, tx_yield } => {
                let fw_rules = self.swarm.behaviour().get_peer_rules(&peer).cloned();
                let _ = tx_yield.send(fw_rules.unwrap_or_else(FirewallRules::empty));
            }
            SwarmOperation::SetPeerRule {
                peer,
                direction,
                rule,
                tx_yield,
            } => {
                self.swarm.behaviour_mut().set_peer_rule(peer, direction, rule);
                let _ = tx_yield.send(());
            }
            SwarmOperation::RemovePeerRule {
                peer,
                direction,
                tx_yield,
            } => {
                self.swarm.behaviour_mut().remove_peer_rule(peer, direction);
                let _ = tx_yield.send(());
            }
            SwarmOperation::BanPeer { peer, tx_yield } => {
                self.swarm.ban_peer_id(peer);
                let _ = tx_yield.send(());
            }
            SwarmOperation::UnbanPeer { peer, tx_yield } => {
                self.swarm.unban_peer_id(peer);
                let _ = tx_yield.send(());
            }
            SwarmOperation::ExportConfig { tx_yield } => {
                let state = self.swarm.behaviour_mut().export_state();
                let _ = tx_yield.send(state);
            }
        }
    }

    fn start_listening(&mut self, address: Multiaddr, tx_yield: oneshot::Sender<Result<Multiaddr, ListenErr>>) {
        match self.swarm.listen_on(address) {
            Ok(listener_id) => {
                self.await_listen.insert(listener_id, tx_yield);
                let new_listener = Listener {
                    addrs: SmallVec::new(),
                    uses_relay: None,
                };
                self.listeners.insert(listener_id, new_listener);
            }
            Err(err) => {
                let _ = tx_yield.send(Err(ListenErr::from(err)));
            }
        }
    }

    // Start listening on a relayed address.
    fn start_relayed_listening(
        &mut self,
        relay: PeerId,
        relay_addr: Option<Multiaddr>,
        tx_yield: oneshot::Sender<Result<Multiaddr, ListenRelayErr>>,
    ) {
        if !self.swarm.behaviour().is_relay_enabled() {
            let err = ListenRelayErr::ProtocolNotSupported;
            let _ = tx_yield.send(Err(err));
            return;
        }

        if let Some(addr) = relay_addr.as_ref() {
            self.swarm.behaviour_mut().add_address(relay, addr.clone());
        }
        let relay_addr = relay_addr.or_else(|| self.swarm.behaviour_mut().addresses_of_peer(&relay).first().cloned());
        let relayed_addr = match relay_addr {
            Some(a) => assemble_relayed_addr(*self.swarm.local_peer_id(), relay, a),
            None => {
                let err = ListenRelayErr::DialRelay(DialErr::NoAddresses);
                let _ = tx_yield.send(Err(err));
                return;
            }
        };
        let listen = self.swarm.listen_on(relayed_addr).map_err(ListenRelayErr::from);
        match listen {
            Ok(listener_id) => {
                self.await_relayed_listen.insert(listener_id, (relay, tx_yield));
                let new_listener = Listener {
                    addrs: SmallVec::new(),
                    uses_relay: Some(relay),
                };
                self.listeners.insert(listener_id, new_listener);
            }
            Err(err) => {
                let _ = tx_yield.send(Err(err));
            }
        }
    }

    // Remove listeners based on the given condition.
    //
    // Return whether there was at least one listener that matches the condition.
    fn remove_listener<F: Fn(&Listener) -> bool>(&mut self, condition_fn: F) -> bool {
        let mut removed_one = false;
        let mut remove_listeners = Vec::new();
        for (id, listener) in self.listeners.iter() {
            if condition_fn(listener) {
                remove_listeners.push(*id);
                removed_one = true;
            }
        }
        for id in remove_listeners {
            let _ = self.listeners.remove(&id);
            let _ = self.swarm.remove_listener(id);
        }
        removed_one
    }

    // Shutdown the task, send errors for all pending operations.
    fn shutdown(mut self) {
        for (_, tx_yield) in self.await_response.drain() {
            let _ = tx_yield.send(Err(OutboundFailure::Shutdown));
        }
        for (_, tx_yield) in self.await_connection.drain() {
            let _ = tx_yield.send(Err(DialErr::Shutdown));
        }
        for (_, tx_yield) in self.await_listen.drain() {
            let _ = tx_yield.send(Err(ListenErr::Shutdown));
        }
        for (_, (_, tx_yield)) in self.await_relayed_listen.drain() {
            let _ = tx_yield.send(Err(ListenRelayErr::Listen(ListenErr::Shutdown)));
        }
    }
}
