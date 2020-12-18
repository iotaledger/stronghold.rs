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
use futures::{channel::mpsc, future, prelude::*};
use libp2p::{
    core::{connection::PendingConnectionError, identity::Keypair, ConnectedPoint, Multiaddr, PeerId},
    swarm::{Swarm, SwarmEvent},
};
use riker::actors::*;

#[derive(Debug, Clone)]
pub enum ConnectPeerError {
    Transport,
    InvalidPeerId,
    ConnectionLimit,
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
/// use stronghold_communication::actor::{CommunicationActor, CommunicationEvent};
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
/// sys.actor_of_args::<CommunicationActor<Request, Response>, _>("communication-actor", (local_keys, chan, None));
/// ```
pub struct CommunicationActor<T: MessageEvent, U: MessageEvent> {
    chan: ChannelRef<CommunicationEvent<T, U>>,
    keypair: Keypair,
    swarm_tx: Option<mpsc::Sender<(CommunicationEvent<T, U>, Sender)>>,
    poll_swarm_handle: Option<future::RemoteHandle<()>>,
    listen_addr: Option<Multiaddr>,
}

impl<T: MessageEvent, U: MessageEvent>
    ActorFactoryArgs<(Keypair, ChannelRef<CommunicationEvent<T, U>>, Option<Multiaddr>)> for CommunicationActor<T, U>
{
    fn create_args(
        (keypair, chan, listen_addr): (Keypair, ChannelRef<CommunicationEvent<T, U>>, Option<Multiaddr>),
    ) -> Self {
        Self {
            chan,
            keypair,
            swarm_tx: None,
            poll_swarm_handle: None,
            listen_addr,
        }
    }
}

impl<T: MessageEvent, U: MessageEvent> Actor for CommunicationActor<T, U> {
    type Msg = CommunicationEvent<T, U>;

    // Subscribe to swarm_outbound to trigger the recv method for them.
    //
    // The swarm_outbound topic can be used by other actors within the ActorSystem to publish messages for remote peers.
    fn pre_start(&mut self, ctx: &Context<Self::Msg>) {
        let topic = Topic::from("to_swarm");
        let sub = Box::new(ctx.myself());
        self.chan.tell(Subscribe { actor: sub, topic }, None);
    }

    // Start a seperate task to manage the communication from and to the swarm
    fn post_start(&mut self, ctx: &Context<Self::Msg>) {
        // Channel to communicate from the CommunicationActor with the swarm task.
        let (swarm_tx, mut swarm_rx) = mpsc::channel(16);
        self.swarm_tx = Some(swarm_tx);

        // Create a P2PNetworkBehaviour for the swarm communication.
        let mut swarm = P2PNetworkBehaviour::<T, U>::init_swarm(self.keypair.clone()).unwrap();
        let listen_addr = self
            .listen_addr
            .clone()
            .unwrap_or_else(|| "/ip4/0.0.0.0/tcp/0".parse().unwrap());
        Swarm::listen_on(&mut swarm, listen_addr).unwrap();

        let chan = self.chan.clone();
        let self_ref = ctx.myself();

        // Kick off the swarm communication in it's own task.
        let handle = ctx.run(future::poll_fn(move |mut tcx: &mut TaskContext<'_>| {
            poll_swarm(self_ref.clone(), &mut tcx, &mut swarm, &mut swarm_rx, &chan)
        }));
        self.poll_swarm_handle = handle.ok();
    }

    // Send shutdown event over tx to swarm task and wait for the swarm to stop listening.
    fn post_stop(&mut self) {
        if let Some(tx) = self.swarm_tx.as_mut() {
            task::block_on(future::poll_fn(move |tcx: &mut TaskContext<'_>| {
                match tx.poll_ready(tcx) {
                    Poll::Ready(Ok(())) => Poll::Ready(tx.start_send((CommunicationEvent::Shutdown, None))),
                    Poll::Ready(err) => Poll::Ready(err),
                    _ => Poll::Pending,
                }
            }))
            .unwrap();
        }
        if let Some(handle) = self.poll_swarm_handle.as_mut() {
            task::block_on(handle);
        }
    }

    // Forward the received events to the task that is managing the swarm communication.
    fn recv(&mut self, _ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        if let Some(tx) = self.swarm_tx.as_mut() {
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
}

// Poll from the swarm for events from remote peers and from the `swarm_tx` channel for events from the local actor, and
// forward them
fn poll_swarm<T: MessageEvent, U: MessageEvent>(
    self_ref: ActorRef<<CommunicationActor<T, U> as Actor>::Msg>,
    tcx: &mut TaskContext<'_>,
    swarm: &mut Swarm<P2PNetworkBehaviour<T, U>>,
    swarm_rx: &mut mpsc::Receiver<(CommunicationEvent<T, U>, Sender)>,
    chan: &ChannelRef<CommunicationEvent<T, U>>,
) -> Poll<()> {
    // Poll for request that are forwarded through the swarm_tx channel and send them over the swarm to remote
    // peers.
    loop {
        let (event, sender_opt) = match swarm_rx.poll_next_unpin(tcx) {
            Poll::Ready(Some(e)) => e,
            Poll::Ready(None) => return Poll::Ready(()),
            Poll::Pending => break,
        };
        match event {
            CommunicationEvent::Message(message) => match message {
                P2PReqResEvent::Req {
                    peer_id,
                    request_id: _,
                    request,
                } => {
                    swarm.send_request(&peer_id, request);
                }
                P2PReqResEvent::Res {
                    peer_id: _,
                    request_id,
                    response,
                } => {
                    let _ = swarm.send_response(response, request_id);
                }
                _ => {}
            },
            CommunicationEvent::ConnectPeer(addr) => {
                let response_event = connect_remote(self_ref.clone(), swarm, chan, addr);
                if let Some(sender) = sender_opt {
                    let _ = sender.try_tell(response_event, self_ref.clone());
                }
            }
            CommunicationEvent::GetSwarmInfo => {
                if let Some(sender) = sender_opt {
                    let peer_id = *Swarm::local_peer_id(&swarm);
                    let listeners = Swarm::listeners(&swarm).cloned().collect();
                    let swarm_info = CommunicationEvent::<T, U>::SwarmInfo { peer_id, listeners };
                    let _ = sender.try_tell(swarm_info, self_ref.clone());
                }
            }
            CommunicationEvent::Shutdown => return Poll::Ready(()),
            _ => {}
        }
    }
    // Poll from the swarm for requests and responses from remote peers and publish them in the channel.
    loop {
        match swarm.poll_next_unpin(tcx) {
            Poll::Ready(Some(event)) => {
                if let P2PEvent::RequestResponse(boxed_event) = event {
                    chan.tell(
                        Publish {
                            msg: CommunicationEvent::Message(boxed_event.deref().clone()),
                            topic: Topic::from("from_swarm"),
                        },
                        Option::<BasicActorRef>::from(self_ref.clone()),
                    )
                }
            }
            Poll::Ready(None) => return Poll::Ready(()),
            Poll::Pending => break,
        }
    }
    Poll::Pending
}

fn connect_remote<T: MessageEvent, U: MessageEvent>(
    self_ref: ActorRef<<CommunicationActor<T, U> as Actor>::Msg>,
    swarm: &mut Swarm<P2PNetworkBehaviour<T, U>>,
    chan: &ChannelRef<CommunicationEvent<T, U>>,
    addr: Multiaddr,
) -> CommunicationEvent<T, U> {
    if Swarm::dial_addr(swarm, addr.clone()).is_ok() {
        loop {
            match task::block_on(swarm.next_event()) {
                SwarmEvent::Behaviour(P2PEvent::RequestResponse(boxed_event)) => {
                    chan.tell(
                        Publish {
                            msg: CommunicationEvent::Message(boxed_event.deref().clone()),
                            topic: Topic::from("from_swarm"),
                        },
                        Option::<BasicActorRef>::from(self_ref.clone()),
                    );
                }
                SwarmEvent::ConnectionEstablished {
                    peer_id,
                    endpoint: ConnectedPoint::Dialer { address },
                    num_established: _,
                } => {
                    if address == addr {
                        return CommunicationEvent::ConnectPeerResult {
                            addr,
                            result: Ok(peer_id),
                        };
                    }
                }
                SwarmEvent::UnreachableAddr {
                    peer_id: _,
                    address,
                    error,
                    attempts_remaining: 0,
                } => {
                    if address == addr {
                        return CommunicationEvent::ConnectPeerResult {
                            addr,
                            result: Err(ConnectPeerError::from(error)),
                        };
                    }
                }
                SwarmEvent::UnknownPeerUnreachableAddr { address, error } => {
                    if address == addr {
                        return CommunicationEvent::ConnectPeerResult {
                            addr,
                            result: Err(ConnectPeerError::from(error)),
                        };
                    }
                }
                _ => {}
            }
        }
    } else {
        CommunicationEvent::ConnectPeerResult {
            addr,
            result: Err(ConnectPeerError::Transport),
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
        chan: ChannelRef<CommunicationEvent<Request, Response>>,
        remote_peer_addr: Multiaddr,
        has_received_response: bool,
    }

    impl ActorFactoryArgs<(ChannelRef<CommunicationEvent<Request, Response>>, Multiaddr)> for LocalActor {
        fn create_args(
            (chan, remote_peer_addr): (ChannelRef<CommunicationEvent<Request, Response>>, Multiaddr),
        ) -> Self {
            LocalActor {
                chan,
                remote_peer_addr,
                has_received_response: false,
            }
        }
    }

    impl Actor for LocalActor {
        type Msg = CommunicationEvent<Request, Response>;

        fn pre_start(&mut self, ctx: &Context<Self::Msg>) {
            let topic = Topic::from("from_swarm");
            let sub = Box::new(ctx.myself());
            self.chan.tell(Subscribe { actor: sub, topic }, None);
            let local_keys = Keypair::generate_ed25519();
            ctx.actor_of_args::<CommunicationActor<Request, Response>, _>(
                "communication",
                (local_keys, self.chan.clone(), None),
            )
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
        chan: ChannelRef<CommunicationEvent<Request, Response>>,
        local_peer_addr: Multiaddr,
    }

    impl ActorFactoryArgs<(ChannelRef<CommunicationEvent<Request, Response>>, Multiaddr)> for RemoteActor {
        fn create_args(
            (chan, local_peer_addr): (ChannelRef<CommunicationEvent<Request, Response>>, Multiaddr),
        ) -> Self {
            RemoteActor { chan, local_peer_addr }
        }
    }

    impl Actor for RemoteActor {
        type Msg = CommunicationEvent<Request, Response>;

        fn pre_start(&mut self, ctx: &Context<Self::Msg>) {
            let topic = Topic::from("from_swarm");
            let sub = Box::new(ctx.myself());
            self.chan.tell(Subscribe { actor: sub, topic }, None);
            let local_keys = Keypair::generate_ed25519();
            ctx.actor_of_args::<CommunicationActor<Request, Response>, _>(
                "communication",
                (local_keys, self.chan.clone(), Some(self.local_peer_addr.clone())),
            )
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
        let chan: ChannelRef<CommunicationEvent<Request, Response>> = channel("p2p", &remote_sys).unwrap();
        remote_sys
            .actor_of_args::<RemoteActor, _>("remote-actor", (chan, remote_addr.clone()))
            .unwrap();

        // local actor system
        let local_sys = ActorSystem::new().unwrap();
        let chan: ChannelRef<CommunicationEvent<Request, Response>> = channel("p2p", &local_sys).unwrap();
        local_sys
            .actor_of_args::<LocalActor, _>("local-actor", (chan, remote_addr))
            .unwrap();
        std::thread::sleep(Duration::new(1, 0));

        task::block_on(async {
            remote_sys.shutdown().await.unwrap();
            local_sys.shutdown().await.unwrap();
        });
    }
}
