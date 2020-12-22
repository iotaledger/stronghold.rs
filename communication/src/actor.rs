// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::behaviour::{
    message::{P2PEvent, P2PReqResEvent},
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
    swarm::{DialError, Swarm, SwarmEvent},
};
use riker::actors::*;

#[derive(Debug, Clone)]
pub enum ConnectPeerError {
    Transport,
    InvalidPeerId,
    ConnectionLimit,
    IO,
    Banned,
    NoAddresses,
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

impl From<DialError> for ConnectPeerError {
    fn from(error: DialError) -> Self {
        match error {
            DialError::Banned => ConnectPeerError::Banned,
            DialError::ConnectionLimit(_) => ConnectPeerError::ConnectionLimit,
            DialError::NoAddresses => ConnectPeerError::NoAddresses,
        }
    }
}

#[derive(Debug, Clone)]
pub enum CommunicationEvent<T, U> {
    Message(P2PReqResEvent<T, U>),
    ConnectPeer(Multiaddr),
    ConnectPeerResult {
        addr: Multiaddr,
        result: Result<PeerId, ConnectPeerError>,
    },
    GetSwarmInfo,
    SwarmInfo {
        peer_id: PeerId,
        listeners: Vec<Multiaddr>,
    },
    Shutdown,
}

#[derive(Clone)]
pub struct CommsActorConfig<T: MessageEvent, U: MessageEvent> {
    keypair: Keypair,
    listen_addr: Option<Multiaddr>,
    chan: Option<ChannelRef<CommunicationEvent<T, U>>>,
    client_ref: Option<BasicActorRef>,
}

impl<T: MessageEvent, U: MessageEvent> CommsActorConfig<T, U> {
    pub fn new(
        keypair: Keypair,
        listen_addr: Option<Multiaddr>,
        chan: Option<ChannelRef<CommunicationEvent<T, U>>>,
        client_ref: Option<BasicActorRef>,
    ) -> CommsActorConfig<T, U> {
        CommsActorConfig {
            keypair,
            listen_addr,
            chan,
            client_ref,
        }
    }
}

/// Actor for the communication to a remote actor over the swarm
///
/// Publishes incoming request- and response-messages from the swarm in the given channel to the "swarm_inbound"
/// topic and subscribes to the "swarm_outbound".  
/// Received `CommunicationEvent::Message` are send to the associated Peer.
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
/// let chan: ChannelRef<CommunicationEvent<Request, Response>> = channel("remote-peer", &sys).unwrap();
/// let config = CommsActorConfig::new(local_keys, None, Some(chan), None);
/// sys.actor_of_args::<CommunicationActor<Request, Response>, _>("communication-actor", config);
/// ```
pub struct CommunicationActor<T: MessageEvent, U: MessageEvent> {
    config: Option<CommsActorConfig<T, U>>,
    swarm_tx: Option<UnboundedSender<CommunicationEvent<T, U>>>,
    poll_swarm_handle: Option<future::RemoteHandle<()>>,
}

impl<T: MessageEvent, U: MessageEvent> ActorFactoryArgs<CommsActorConfig<T, U>> for CommunicationActor<T, U> {
    fn create_args(config: CommsActorConfig<T, U>) -> Self {
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

    // Subscribe to swarm_outbound to trigger the recv method for them.
    //
    // The swarm_outbound topic can be used by other actors within the ActorSystem to publish messages for remote peers.
    fn pre_start(&mut self, ctx: &Context<Self::Msg>) {
        if let Some(chan) = self.config.as_ref().unwrap().chan.clone() {
            let topic = Topic::from("to_swarm");
            let sub = Box::new(ctx.myself());
            chan.tell(Subscribe { actor: sub, topic }, None);
        }
    }

    // Start a seperate task to manage the communication from and to the swarm
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
        self.tx_to_swarm_task(CommunicationEvent::Shutdown);
        if let Some(handle) = self.poll_swarm_handle.as_mut() {
            task::block_on(handle);
        }
    }

    // Forward the received events to the task that is managing the swarm communication.
    fn recv(&mut self, _ctx: &Context<Self::Msg>, msg: Self::Msg, _sender: Sender) {
        self.tx_to_swarm_task(msg);
    }
}

impl<T: MessageEvent, U: MessageEvent> CommunicationActor<T, U> {
    fn tx_to_swarm_task(&mut self, msg: CommunicationEvent<T, U>) {
        let tx = &mut self.swarm_tx.as_mut().unwrap();
        task::block_on(future::poll_fn(move |tcx: &mut TaskContext<'_>| {
            match tx.poll_ready(tcx) {
                Poll::Ready(Ok(())) => Poll::Ready(tx.start_send(msg.clone())),
                Poll::Ready(err) => Poll::Ready(err),
                _ => Poll::Pending,
            }
        }))
        .unwrap();
    }
}

struct SwarmTask<T: MessageEvent, U: MessageEvent> {
    swarm: Swarm<P2PNetworkBehaviour<T, U>>,
    chan: Option<ChannelRef<CommunicationEvent<T, U>>>,
    client_ref: Option<BasicActorRef>,
    swarm_rx: UnboundedReceiver<CommunicationEvent<T, U>>,
    self_ref: BasicActorRef,
}

impl<T: MessageEvent, U: MessageEvent> SwarmTask<T, U> {
    fn new(
        config: CommsActorConfig<T, U>,
        swarm_rx: UnboundedReceiver<CommunicationEvent<T, U>>,
        self_ref: BasicActorRef,
    ) -> Self {
        // Create a P2PNetworkBehaviour for the swarm communication.
        let mut swarm = P2PNetworkBehaviour::<T, U>::init_swarm(config.keypair.clone()).unwrap();
        let listen_addr = config
            .listen_addr
            .clone()
            .unwrap_or_else(|| "/ip4/0.0.0.0/tcp/0".parse().unwrap());
        Swarm::listen_on(&mut swarm, listen_addr).unwrap();
        SwarmTask {
            swarm,
            chan: config.chan,
            client_ref: config.client_ref,
            swarm_rx,
            self_ref,
        }
    }

    // Poll from the swarm for events from remote peers and from the `swarm_tx` channel for events from the local actor,
    // and forward them
    async fn poll_swarm(mut self) {
        loop {
            select! {
                actor_event = self.swarm_rx.next().fuse()=> {
                    if actor_event.is_none() || self.handle_actor_event(actor_event.unwrap()).is_none(){
                        return
                    }
                },
                swarm_event = self.swarm.next_event().fuse() => self.handle_swarm_event(swarm_event),
            };
        }
    }

    // Poll for request that are forwarded through the swarm_tx channel and send them over the swarm to remote peers.
    fn handle_actor_event(&mut self, event: CommunicationEvent<T, U>) -> Option<()> {
        match event {
            CommunicationEvent::Message(message) => match message {
                P2PReqResEvent::Req {
                    peer_id,
                    request_id: _,
                    request,
                } => {
                    self.swarm.send_request(&peer_id, request);
                }
                P2PReqResEvent::Res {
                    peer_id: _,
                    request_id,
                    response,
                } => {
                    let _ = self.swarm.send_response(response, request_id);
                }
                _ => {}
            },
            CommunicationEvent::ConnectPeer(addr) => {
                if Swarm::dial_addr(&mut self.swarm, addr.clone()).is_err() {
                    let response = CommunicationEvent::ConnectPeerResult {
                        addr,
                        result: Err(ConnectPeerError::ConnectionLimit),
                    };
                    self.tell_actor(response);
                }
            }
            CommunicationEvent::GetSwarmInfo => {
                let peer_id = *Swarm::local_peer_id(&self.swarm);
                let listeners = Swarm::listeners(&self.swarm).cloned().collect();
                let swarm_info = CommunicationEvent::<T, U>::SwarmInfo { peer_id, listeners };
                self.tell_actor(swarm_info);
            }
            CommunicationEvent::Shutdown => return None,
            _ => {}
        }
        Some(())
    }

    // Poll from the swarm for requests and responses from remote peers and publish them in the channel.
    fn handle_swarm_event<HandleErr>(&mut self, event: SwarmEvent<P2PEvent<T, U>, HandleErr>) {
        let msg = match event {
            SwarmEvent::Behaviour(P2PEvent::RequestResponse(boxed_event)) => {
                Some(CommunicationEvent::Message(boxed_event.deref().clone()))
            }
            SwarmEvent::ConnectionEstablished {
                peer_id,
                endpoint: ConnectedPoint::Dialer { address },
                num_established: _,
            } => Some(CommunicationEvent::ConnectPeerResult {
                addr: address,
                result: Ok(peer_id),
            }),
            SwarmEvent::UnreachableAddr {
                peer_id: _,
                address,
                error,
                attempts_remaining: 0,
            } => Some(CommunicationEvent::ConnectPeerResult {
                addr: address,
                result: Err(ConnectPeerError::from(error)),
            }),
            SwarmEvent::UnknownPeerUnreachableAddr { address, error } => Some(CommunicationEvent::ConnectPeerResult {
                addr: address,
                result: Err(ConnectPeerError::from(error)),
            }),
            _ => None,
        };
        if let Some(msg) = msg {
            self.tell_actor(msg);
        }
    }

    fn tell_actor(&mut self, msg: CommunicationEvent<T, U>) {
        if let Some(chan) = self.chan.as_ref() {
            chan.tell(
                Publish {
                    msg: msg.clone(),
                    topic: Topic::from("from_swarm"),
                },
                Some(self.self_ref.clone()),
            )
        }
        if let Some(client) = self.client_ref.as_ref() {
            let _ = client.try_tell(msg, self.self_ref.clone());
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use core::time::Duration;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    enum Request {
        Ping,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    enum Response {
        Pong,
    }

    struct LocalActor {
        remote_peer_addr: Multiaddr,
        has_received_response: bool,
    }

    impl ActorFactoryArgs<Multiaddr> for LocalActor {
        fn create_args(remote_peer_addr: Multiaddr) -> Self {
            LocalActor {
                remote_peer_addr,
                has_received_response: false,
            }
        }
    }

    impl Actor for LocalActor {
        type Msg = CommunicationEvent<Request, Response>;

        fn pre_start(&mut self, ctx: &Context<Self::Msg>) {
            let self_ref = BasicActorRef::from(ctx.myself());
            let local_keys = Keypair::generate_ed25519();
            let config = CommsActorConfig::new(local_keys, None, None, Some(self_ref));
            ctx.actor_of_args::<CommunicationActor<Request, Response>, _>("communication", config)
                .unwrap();
        }

        fn post_start(&mut self, ctx: &Context<Self::Msg>) {
            let communication_actor = ctx.select("communication").unwrap();
            let event = CommunicationEvent::<Request, Response>::ConnectPeer(self.remote_peer_addr.clone());
            communication_actor.try_tell(event, ctx.myself());
        }

        fn supervisor_strategy(&self) -> Strategy {
            Strategy::Escalate
        }

        fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, _sender: Sender) {
            if let CommunicationEvent::Message(P2PReqResEvent::Res {
                peer_id: _,
                request_id: _,
                response: _,
            }) = msg
            {
                self.has_received_response = true;
            } else if let CommunicationEvent::ConnectPeerResult { addr: _, result } = msg {
                let peer_id = result.expect("Panic due to no network connection");
                let request = CommunicationEvent::<Request, Response>::Message(P2PReqResEvent::Req {
                    peer_id,
                    request_id: None,
                    request: Request::Ping,
                });
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
            let self_ref = BasicActorRef::from(ctx.myself());
            let local_keys = Keypair::generate_ed25519();
            let config = CommsActorConfig {
                keypair: local_keys,
                listen_addr: Some(self.listening_addr.clone()),
                chan: None,
                client_ref: Some(self_ref),
            };
            ctx.actor_of_args::<CommunicationActor<Request, Response>, _>("communication", config)
                .unwrap();
        }

        fn supervisor_strategy(&self) -> Strategy {
            Strategy::Escalate
        }

        fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, _sender: Sender) {
            if let CommunicationEvent::Message(P2PReqResEvent::Req {
                peer_id,
                request_id: Some(request_id),
                request: Request::Ping,
            }) = msg
            {
                let response = CommunicationEvent::<Request, Response>::Message(P2PReqResEvent::Res {
                    peer_id,
                    request_id,
                    response: Response::Pong,
                });
                let communication_actor = ctx.select("*").unwrap();
                communication_actor.try_tell(response, ctx.myself());
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
            .actor_of_args::<LocalActor, _>("local-actor", remote_addr)
            .unwrap();
        std::thread::sleep(Duration::new(1, 0));

        task::block_on(async {
            remote_sys.shutdown().await.unwrap();
            local_sys.shutdown().await.unwrap();
        });
    }
}
