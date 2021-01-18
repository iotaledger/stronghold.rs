// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::behaviour::{
    message::{P2PEvent, P2PInboundFailure, P2POutboundFailure, P2PReqResEvent},
    MessageEvent, P2PNetworkBehaviour,
};
use async_std::task;
use core::{
    ops::Deref,
    task::{Context as TaskContext, Poll},
};
use futures::{
    channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender},
    future,
    prelude::*,
    select,
};
use libp2p::{
    core::{connection::PendingConnectionError, identity::Keypair, ConnectedPoint, Multiaddr, PeerId},
    request_response::RequestId,
    swarm::{Swarm, SwarmEvent},
};
use riker::actors::*;
use std::{collections::HashMap, string::ToString};

/// Errors that can occur in the context of a pending `Connection`.
#[derive(Debug, Clone)]
pub enum ConnectPeerError {
    /// An error occurred while negotiating the transport protocol(s).
    Transport,
    /// The peer identity obtained on the connection did not
    /// match the one that was expected or is otherwise invalid.
    InvalidPeerId,
    /// The connection was dropped because the connection limit
    /// for a peer has been reached.
    ConnectionLimit,
    /// An I/O error occurred on the connection.
    IO,
}

impl<TTransErr> From<PendingConnectionError<TTransErr>> for ConnectPeerError {
    fn from(error: PendingConnectionError<TTransErr>) -> Self {
        match error {
            PendingConnectionError::Transport(_) => ConnectPeerError::Transport,
            PendingConnectionError::InvalidPeerId => ConnectPeerError::InvalidPeerId,
            PendingConnectionError::ConnectionLimit(_) => ConnectPeerError::ConnectionLimit,
            PendingConnectionError::IO(_) => ConnectPeerError::IO,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ResponseFailure {
    Inbound(P2PInboundFailure),
    Outbound(P2POutboundFailure),
}

/// Events for communication with the [`CommunicationActor`].
///
/// T and U are the request and response types of the messages to remote peers,
/// and should implement Serialize and Deserialize since this is required by the protocol.
#[derive(Debug, Clone)]
pub enum CommunicationEvent<T, U> {
    /// Send request to remote peer.
    Request {
        peer_id: PeerId,
        request_id: Option<RequestId>,
        request: T,
    },
    /// Response from remote peer
    Response {
        request_id: RequestId,
        result: Result<U, ResponseFailure>,
    },
    /// Dial a new peer on the address.
    ConnectPeer { addr: Multiaddr, peer_id: PeerId },
    /// Outcome of [`ConnectPeer`].
    ConnectPeerResult(Result<PeerId, ConnectPeerError>),
    /// Get information about the local peer.
    GetSwarmInfo,
    /// Information about the local peer.
    /// Outcome of [`GetSwarmInfo`].
    SwarmInfo { peer_id: PeerId, listeners: Vec<Multiaddr> },
    /// Sets the actor ref for the that the communication actor talks to
    SetClientRef(BasicActorRef),
    /// Shutdown the swarm task that is handling the swarm and all communication to remote peers.
    Shutdown,
}

/// Configure the `CommunicationActor` upon creation.
#[derive(Clone)]
pub struct CommsActorConfig {
    /// The keypair that will be used to build and authenticate the transport.
    keypair: Keypair,
    /// Specific address that the peer should listen on, per default this is assigned by the OS.
    listen_addr: Option<Multiaddr>,
    /// If a actor ref is provided, the `CommunicationActor` will try to directly tell this actor
    /// the events.
    /// This is independently of the `chan` attribute.
    client_ref: BasicActorRef,
}

impl CommsActorConfig {
    pub fn new(keypair: Keypair, listen_addr: Option<Multiaddr>, client_ref: BasicActorRef) -> CommsActorConfig {
        CommsActorConfig {
            keypair,
            listen_addr,
            client_ref,
        }
    }
}

/// Actor for the communication to a remote peer over the swarm.
///
/// Publishes incoming request- and response-messages from the swarm to a channel and/ or a client
/// actor, depending on the [`CommsActorConfig`].
/// Received [`CommunicationEvent::Message`]s are send to the associated Peer.
///
///
/// ```no_run
/// use libp2p::identity::Keypair;
/// use riker::actors::*;
/// use serde::{Deserialize, Serialize};
/// use stronghold_communication::actor::{CommsActorConfig, CommunicationActor, CommunicationEvent};
///
/// #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// pub enum Request {
///     Ping,
/// }
///
/// #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// pub enum Response {
///     Pong,
/// }
///
/// let local_keys = Keypair::generate_ed25519();
/// let sys = ActorSystem::new().unwrap();
/// // let config = CommsActorConfig::new(local_keys, None);
/// // sys.actor_of_args::<CommunicationActor<Request, Response>, _>("communication-actor", config);
/// ```
pub struct CommunicationActor<T: MessageEvent, U: MessageEvent> {
    config: Option<CommsActorConfig>,
    swarm_tx: Option<UnboundedSender<(CommunicationEvent<T, U>, Sender)>>,
    poll_swarm_handle: Option<future::RemoteHandle<()>>,
}

impl<T: MessageEvent, U: MessageEvent> ActorFactoryArgs<CommsActorConfig> for CommunicationActor<T, U> {
    fn create_args(config: CommsActorConfig) -> Self {
        // Channel to communicate from the CommunicationActor with the swarm task.
        Self {
            config: Some(config),
            swarm_tx: None,
            poll_swarm_handle: None,
        }
    }
}

impl<T: MessageEvent, U: MessageEvent> Actor for CommunicationActor<T, U> {
    type Msg = CommunicationEvent<T, U>;

    // Start a separate task to manage the communication from and to the swarm
    fn post_start(&mut self, ctx: &Context<Self::Msg>) {
        let (swarm_tx, swarm_rx) = unbounded();
        self.swarm_tx = Some(swarm_tx);
        let self_actor_ref = BasicActorRef::from(ctx.myself());
        let swarm_task = SwarmTask::<T, U>::new(self.config.take().unwrap(), swarm_rx, self_actor_ref);

        // Kick off the swarm communication in it's own task.
        self.poll_swarm_handle = ctx.run(swarm_task.poll_swarm()).ok()
    }

    // Send shutdown event over tx to swarm task and wait for the swarm to stop listening.
    fn post_stop(&mut self) {
        self.tx_to_swarm_task(CommunicationEvent::Shutdown, None);
        if let Some(handle) = self.poll_swarm_handle.as_mut() {
            task::block_on(handle);
        }
    }

    // Forward the received events to the task that is managing the swarm communication.
    fn recv(&mut self, _ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        self.tx_to_swarm_task(msg, sender);
    }
}

impl<T: MessageEvent, U: MessageEvent> CommunicationActor<T, U> {
    // Uses the mpsc channel to send messages to the swarm task.
    fn tx_to_swarm_task(&mut self, msg: CommunicationEvent<T, U>, sender: Sender) {
        let tx = &mut self.swarm_tx.as_mut().unwrap();
        task::block_on(future::poll_fn(move |tcx: &mut TaskContext<'_>| {
            match tx.poll_ready(tcx) {
                Poll::Ready(Ok(())) => Poll::Ready(tx.start_send((msg.clone(), sender.clone()))),
                Poll::Ready(err) => Poll::Ready(err),
                _ => Poll::Pending,
            }
        }))
        .unwrap();
    }
}

struct SenderMap {
    map: HashMap<String, Sender>,
}

impl SenderMap {
    fn new() -> Self {
        SenderMap { map: HashMap::new() }
    }
    fn insert<T: ToString>(&mut self, key: T, sender: Sender) {
        self.map.insert(key.to_string(), sender);
    }

    fn take<T: ToString>(&mut self, key: T) -> Option<Sender> {
        self.map.remove(&key.to_string())
    }
}

// Separate task that manages the swarm communication.
struct SwarmTask<T: MessageEvent, U: MessageEvent> {
    swarm: Swarm<P2PNetworkBehaviour<T, U>>,
    client_ref: BasicActorRef,
    swarm_rx: UnboundedReceiver<(CommunicationEvent<T, U>, Sender)>,
    self_ref: BasicActorRef,
    sender_map: SenderMap,
}

impl<T: MessageEvent, U: MessageEvent> SwarmTask<T, U> {
    fn new(
        config: CommsActorConfig,
        swarm_rx: UnboundedReceiver<(CommunicationEvent<T, U>, Sender)>,
        self_ref: BasicActorRef,
    ) -> Self {
        // Create a P2PNetworkBehaviour for the swarm communication.
        let mut swarm = P2PNetworkBehaviour::<T, U>::init_swarm(config.keypair.clone()).unwrap();
        let listen_addr = config
            .listen_addr
            .clone()
            .unwrap_or_else(|| "/ip4/127.0.0.1/tcp/0".parse().unwrap());
        Swarm::listen_on(&mut swarm, listen_addr).unwrap();
        SwarmTask {
            swarm,
            client_ref: config.client_ref,
            swarm_rx,
            self_ref,
            sender_map: SenderMap::new(),
        }
    }

    // Poll from the swarm for events from remote peers, and from the `swarm_tx` channel for events from the local
    // actor, and forward them.
    async fn poll_swarm(mut self) {
        loop {
            select! {
                actor_event = self.swarm_rx.next().fuse() => {
                    if let Some((message, sender)) = actor_event {
                        if self.handle_actor_event(message, sender).is_none() {
                            return
                        }
                    } else {
                        return
                    }
                },
                swarm_event = self.swarm.next_event().fuse() => self.handle_swarm_event(swarm_event),
            };
        }
    }

    // Handle the messages that are received from other actors in the system..
    fn handle_actor_event(&mut self, event: CommunicationEvent<T, U>, sender: Sender) -> Option<()> {
        match event {
            CommunicationEvent::Request {
                peer_id,
                request_id: _,
                request,
            } => {
                let request_id = self.swarm.send_request(&peer_id, request);
                self.sender_map.insert(request_id, sender);
            }
            CommunicationEvent::Response {
                result: Ok(response),
                request_id,
            } => {
                let _ = self.swarm.send_response(response, request_id);
            }
            CommunicationEvent::ConnectPeer { addr, peer_id } => {
                if Swarm::dial(&mut self.swarm, &peer_id).is_ok()
                    || Swarm::dial_addr(&mut self.swarm, addr.clone()).is_ok()
                {
                    self.sender_map.insert(addr, sender);
                } else if let Some(sender) = sender {
                    let response =
                        CommunicationEvent::<T, U>::ConnectPeerResult(Err(ConnectPeerError::ConnectionLimit));
                    sender.try_tell(response, self.self_ref.clone()).unwrap();
                }
            }
            CommunicationEvent::GetSwarmInfo => {
                if let Some(sender) = sender {
                    let peer_id = *Swarm::local_peer_id(&self.swarm);
                    let listeners = Swarm::listeners(&self.swarm).cloned().collect();
                    let swarm_info = CommunicationEvent::<T, U>::SwarmInfo { peer_id, listeners };
                    sender.try_tell(swarm_info, self.self_ref.clone()).unwrap();
                }
            }
            CommunicationEvent::SetClientRef(actor_ref) => self.client_ref = actor_ref,
            CommunicationEvent::Shutdown => return None,
            _ => {}
        }
        Some(())
    }

    // Poll from the swarm for requests and responses from remote peers, and publish them in the channel.
    fn handle_swarm_event<HandleErr>(&mut self, event: SwarmEvent<P2PEvent<T, U>, HandleErr>) {
        match event {
            SwarmEvent::Behaviour(P2PEvent::RequestResponse(boxed_event)) => match boxed_event.deref().clone() {
                P2PReqResEvent::Res {
                    peer_id: _,
                    request_id,
                    response,
                } => {
                    if let Some(Some(actor_ref)) = self.sender_map.take(&request_id) {
                        let msg = CommunicationEvent::<T, U>::Response {
                            request_id,
                            result: Ok(response),
                        };
                        actor_ref.try_tell(msg, Some(self.self_ref.clone())).unwrap();
                    }
                }
                P2PReqResEvent::Req {
                    peer_id,
                    request_id,
                    request,
                } => {
                    let msg = CommunicationEvent::<T, U>::Request {
                        peer_id,
                        request_id,
                        request,
                    };
                    println!("\nclient_ref: {}\n", self.client_ref);
                    self.client_ref.try_tell(msg, Some(self.self_ref.clone())).unwrap();
                }
                P2PReqResEvent::InboundFailure {
                    peer_id: _,
                    request_id,
                    error,
                } => {
                    if let Some(Some(actor_ref)) = self.sender_map.take(&request_id) {
                        let msg = CommunicationEvent::<T, U>::Response {
                            request_id,
                            result: Err(ResponseFailure::Inbound(error)),
                        };
                        actor_ref.try_tell(msg, Some(self.self_ref.clone())).unwrap();
                    }
                }
                P2PReqResEvent::OutboundFailure {
                    peer_id: _,
                    request_id,
                    error,
                } => {
                    if let Some(Some(actor_ref)) = self.sender_map.take(&request_id) {
                        let msg = CommunicationEvent::<T, U>::Response {
                            request_id,
                            result: Err(ResponseFailure::Outbound(error)),
                        };
                        actor_ref.try_tell(msg, Some(self.self_ref.clone())).unwrap();
                    }
                }
                _ => {}
            },
            SwarmEvent::ConnectionEstablished {
                peer_id,
                endpoint: ConnectedPoint::Dialer { address },
                num_established: _,
            } => {
                if let Some(Some(actor_ref)) = self.sender_map.take(address) {
                    let msg = CommunicationEvent::<T, U>::ConnectPeerResult(Ok(peer_id));
                    actor_ref.try_tell(msg, Some(self.self_ref.clone())).unwrap();
                }
            }
            SwarmEvent::UnreachableAddr {
                peer_id: _,
                address,
                error,
                attempts_remaining: 0,
            }
            | SwarmEvent::UnknownPeerUnreachableAddr { address, error } => {
                if let Some(Some(actor_ref)) = self.sender_map.take(address) {
                    let msg = CommunicationEvent::<T, U>::ConnectPeerResult(Err(ConnectPeerError::from(error)));
                    actor_ref.try_tell(msg, Some(self.self_ref.clone())).unwrap();
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use core::time::Duration;
    use serde::{Deserialize, Serialize};
    use std::sync::{Arc, Mutex};

    use futures::{
        channel::oneshot::{channel, Sender as ChannelSender},
        future::RemoteHandle,
        FutureExt,
    };

    #[derive(Debug, Clone, Serialize, Deserialize)]
    enum Request {
        Ping,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    enum Response {
        Pong,
    }

    struct LocalActor {
        remote_peer: (PeerId, Multiaddr),
        has_received_response: bool,
    }

    impl ActorFactoryArgs<(PeerId, Multiaddr)> for LocalActor {
        fn create_args(remote_peer: (PeerId, Multiaddr)) -> Self {
            LocalActor {
                remote_peer,
                has_received_response: false,
            }
        }
    }

    impl Actor for LocalActor {
        type Msg = CommunicationEvent<Request, Response>;

        fn pre_start(&mut self, ctx: &Context<Self::Msg>) {
            let local_keys = Keypair::generate_ed25519();
            let self_ref = BasicActorRef::from(ctx.myself());
            let config = CommsActorConfig::new(local_keys, None, self_ref);
            ctx.actor_of_args::<CommunicationActor<Request, Response>, _>("communication", config)
                .unwrap();
        }

        fn post_start(&mut self, ctx: &Context<Self::Msg>) {
            let communication_actor = ctx.select("communication").unwrap();
            let event = CommunicationEvent::<Request, Response>::ConnectPeer {
                addr: self.remote_peer.1.clone(),
                peer_id: self.remote_peer.0,
            };
            communication_actor.try_tell(event, ctx.myself());
        }

        fn supervisor_strategy(&self) -> Strategy {
            Strategy::Escalate
        }

        fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, _sender: Sender) {
            if let CommunicationEvent::Response {
                request_id: _,
                result: _,
            } = msg
            {
                self.has_received_response = true;
            } else if let CommunicationEvent::ConnectPeerResult(result) = msg {
                let peer_id = result.expect("Panic due to no network connection");
                let request = CommunicationEvent::<Request, Response>::Request {
                    peer_id,
                    request_id: None,
                    request: Request::Ping,
                };
                let communication_actor = ctx.select("*").unwrap();
                communication_actor.try_tell(request, ctx.myself());
            }
        }

        fn post_stop(&mut self) {
            assert!(self.has_received_response);
        }
    }

    struct RemoteActor {
        listening_addr: Multiaddr,
    }

    impl ActorFactoryArgs<Multiaddr> for RemoteActor {
        fn create_args(listening_addr: Multiaddr) -> Self {
            RemoteActor { listening_addr }
        }
    }

    impl Actor for RemoteActor {
        type Msg = CommunicationEvent<Request, Response>;

        fn pre_start(&mut self, ctx: &Context<Self::Msg>) {
            let local_keys = Keypair::generate_ed25519();
            let self_ref = BasicActorRef::from(ctx.myself());
            let config = CommsActorConfig::new(local_keys, Some(self.listening_addr.clone()), self_ref);
            ctx.actor_of_args::<CommunicationActor<Request, Response>, _>("communication", config)
                .unwrap();
        }

        fn supervisor_strategy(&self) -> Strategy {
            Strategy::Escalate
        }

        fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
            if let CommunicationEvent::Request {
                peer_id: _,
                request_id: Some(request_id),
                request: Request::Ping,
            } = msg
            {
                let response = CommunicationEvent::<Request, Response>::Response {
                    request_id,
                    result: Ok(Response::Pong),
                };
                sender.unwrap().try_tell(response, ctx.myself()).unwrap();
            }
        }
    }

    #[test]
    fn msg_external_actor() {
        let remote_addr: Multiaddr = "/ip4/127.0.0.1/tcp/8090".parse().unwrap();

        // remote actor system
        let remote_sys = ActorSystem::new().unwrap();
        remote_sys
            .actor_of_args::<RemoteActor, _>("remote-actor", remote_addr.clone())
            .unwrap();

        // local actor system
        let local_sys = ActorSystem::new().unwrap();
        local_sys
            .actor_of_args::<LocalActor, _>("local-actor", (PeerId::random(), remote_addr))
            .unwrap();
        std::thread::sleep(Duration::new(1, 0));

        task::block_on(async {
            remote_sys.shutdown().await.unwrap();
            local_sys.shutdown().await.unwrap();
        });
    }

    #[derive(Clone)]
    struct BlankActor;

    impl ActorFactory for BlankActor {
        fn create() -> Self {
            BlankActor
        }
    }

    impl Actor for BlankActor {
        type Msg = String;

        fn recv(&mut self, _ctx: &Context<Self::Msg>, _msg: Self::Msg, _sender: Sender) {}
    }

    #[test]
    fn ask_swarm_info() {
        let sys = ActorSystem::new().unwrap();
        let blank = sys.actor_of::<BlankActor>("blank").unwrap();

        let local_keys = crate::generate_new_keypair();
        let client_ref = BasicActorRef::from(blank);
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/8095".parse().unwrap();
        let config = CommsActorConfig::new(local_keys.clone(), Some(addr.clone()), client_ref);
        let communication_actor = sys
            .actor_of_args::<CommunicationActor<String, String>, _>("communication", config)
            .unwrap();
        let result = task::block_on(ask::<_, _, CommunicationEvent<String, String>, _>(
            &sys,
            &communication_actor,
            CommunicationEvent::GetSwarmInfo,
        ));
        match result {
            CommunicationEvent::SwarmInfo { peer_id, listeners } => {
                assert_eq!(PeerId::from(local_keys.public()), peer_id);
                assert!(listeners.contains(&addr));
            }
            _ => panic!(),
        }
    }

    #[derive(Clone)]
    struct TargetActor;

    impl ActorFactory for TargetActor {
        fn create() -> Self {
            TargetActor
        }
    }

    impl Actor for TargetActor {
        type Msg = CommunicationEvent<String, String>;

        fn recv(&mut self, _ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
            if let CommunicationEvent::Request {
                peer_id: _,
                request_id: Some(request_id),
                request,
            } = msg
            {
                let response = CommunicationEvent::<String, _>::Response {
                    request_id,
                    result: Ok(request),
                };
                sender.unwrap().try_tell(response, None).unwrap();
            } else {
                panic!();
            }
        }
    }

    #[test]
    fn ask_request() {
        // start remote actor system
        let remote_sys = ActorSystem::new().unwrap();
        let target_actor = BasicActorRef::from(remote_sys.actor_of::<TargetActor>("target").unwrap());
        let remote_config = CommsActorConfig::new(crate::generate_new_keypair(), None, target_actor);
        let remote_comms = remote_sys
            .actor_of_args::<CommunicationActor<String, String>, _>("communication", remote_config)
            .unwrap();

        // start local actor system
        let local_sys = ActorSystem::new().unwrap();
        let blank_actor = local_sys.actor_of::<BlankActor>("blank").unwrap();
        let local_config = CommsActorConfig::new(crate::generate_new_keypair(), None, BasicActorRef::from(blank_actor));
        let local_comms = local_sys
            .actor_of_args::<CommunicationActor<String, String>, _>("communication", local_config)
            .unwrap();

        std::thread::sleep(Duration::new(1, 0));

        // obtain information about the remote peer id and listeners
        let result = task::block_on(ask::<_, _, CommunicationEvent<String, String>, _>(
            &remote_sys,
            &remote_comms,
            CommunicationEvent::GetSwarmInfo,
        ));
        let (remote_peer_id, listeners) = match result {
            CommunicationEvent::SwarmInfo { peer_id, listeners } => (peer_id, listeners),
            _ => panic!(),
        };

        // connect remote peer
        match task::block_on(ask::<_, _, CommunicationEvent<String, String>, _>(
            &local_sys,
            &local_comms,
            CommunicationEvent::ConnectPeer {
                addr: listeners.last().unwrap().clone(),
                peer_id: remote_peer_id,
            },
        )) {
            CommunicationEvent::ConnectPeerResult(Ok(peer_id)) => assert_eq!(peer_id, remote_peer_id),
            _ => panic!(),
        };

        // send message to remote peer
        let test_msg = String::from("test");
        match task::block_on(ask::<_, _, CommunicationEvent<String, String>, _>(
            &local_sys,
            &local_comms,
            CommunicationEvent::Request {
                peer_id: remote_peer_id,
                request_id: None,
                request: test_msg.clone(),
            },
        )) {
            CommunicationEvent::Response {
                request_id: _,
                result: Ok(echoed_msg),
            } => assert_eq!(test_msg, echoed_msg),
            _ => panic!(),
        };
        local_sys.stop(&local_comms);
        remote_sys.stop(&remote_comms);
    }

    fn ask<Msg, Ctx, R, T>(ctx: &Ctx, receiver: &T, msg: Msg) -> RemoteHandle<R>
    where
        Msg: Message,
        R: Message,
        Ctx: TmpActorRefFactory + Run,
        T: Tell<Msg>,
    {
        let (tx, rx) = channel::<R>();
        let tx = Arc::new(Mutex::new(Some(tx)));

        let props = Props::new_from_args(Box::new(AskActor::boxed), tx);
        let actor = ctx.tmp_actor_of_props(props).unwrap();
        receiver.tell(msg, Some(actor.into()));

        ctx.run(rx.map(|r| r.unwrap())).unwrap()
    }

    struct AskActor<Msg> {
        tx: Arc<Mutex<Option<ChannelSender<Msg>>>>,
    }

    impl<Msg: Message> AskActor<Msg> {
        fn boxed(tx: Arc<Mutex<Option<ChannelSender<Msg>>>>) -> BoxActor<Msg> {
            let ask = AskActor { tx };
            Box::new(ask)
        }
    }

    impl<Msg: Message> Actor for AskActor<Msg> {
        type Msg = Msg;

        fn recv(&mut self, ctx: &Context<Msg>, msg: Msg, _: Sender) {
            if let Ok(mut tx) = self.tx.lock() {
                tx.take().unwrap().send(msg).unwrap();
            }
            ctx.stop(&ctx.myself);
        }
    }
}
