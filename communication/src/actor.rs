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
    core::{
        connection::{ListenerId, PendingConnectionError},
        identity::Keypair,
        ConnectedPoint, Multiaddr,
    },
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
        result: Result<(), ConnectPeerError>,
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
/// use communication::actor::{CommunicationActor, CommunicationEvent};
/// use libp2p::identity::Keypair;
/// use riker::actors::*;
/// use serde::{Deserialize, Serialize};
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
/// sys.actor_of_args::<CommunicationActor<Request, Response>, _>("communication-actor", (local_keys, chan));
/// ```
pub struct CommunicationActor<T: MessageEvent, U: MessageEvent> {
    chan: ChannelRef<CommunicationEvent<T, U>>,
    keypair: Keypair,
    swarm_tx: Option<mpsc::Sender<CommunicationEvent<T, U>>>,
    poll_swarm_handle: Option<future::RemoteHandle<()>>,
}

impl<T: MessageEvent, U: MessageEvent> ActorFactoryArgs<(Keypair, ChannelRef<CommunicationEvent<T, U>>)>
    for CommunicationActor<T, U>
{
    fn create_args((keypair, chan): (Keypair, ChannelRef<CommunicationEvent<T, U>>)) -> Self {
        Self {
            chan,
            keypair,
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
        let topic = Topic::from("swarm_outbound");
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
        let listener = Swarm::listen_on(&mut swarm, "/ip4/0.0.0.0/tcp0".parse().unwrap()).unwrap();

        let chan = self.chan.clone();
        let topic = Topic::from("swarm_inbound");

        // Kick off the swarm communication in it's own task.
        let handle = ctx.run(future::poll_fn(move |mut tcx: &mut TaskContext<'_>| {
            poll_swarm(&mut tcx, &mut swarm, &mut swarm_rx, &chan, topic.clone(), listener)
        }));
        self.poll_swarm_handle = handle.ok();
    }

    // Send shutdown event over tx to swarm task and wait for the swarm to stop listening.
    fn post_stop(&mut self) {
        if let Some(tx) = self.swarm_tx.as_mut() {
            task::block_on(future::poll_fn(move |tcx: &mut TaskContext<'_>| {
                match tx.poll_ready(tcx) {
                    Poll::Ready(Ok(())) => Poll::Ready(tx.start_send(CommunicationEvent::Shutdown)),
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
    fn recv(&mut self, _ctx: &Context<Self::Msg>, msg: Self::Msg, _sender: Sender) {
        if let Some(tx) = self.swarm_tx.as_mut() {
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
}

// Poll from the swarm for events from remote peers and from the `swarm_tx` channel for events from the local actor, and
// forward them
fn poll_swarm<T: MessageEvent, U: MessageEvent>(
    tcx: &mut TaskContext<'_>,
    mut swarm: &mut Swarm<P2PNetworkBehaviour<T, U>>,
    swarm_rx: &mut mpsc::Receiver<CommunicationEvent<T, U>>,
    chan: &ChannelRef<CommunicationEvent<T, U>>,
    topic: Topic,
    listener: ListenerId,
) -> Poll<()> {
    // Poll for request that are forwarded through the swarm_tx channel and send them over the swarm to remote
    // peers.
    loop {
        let event = match swarm_rx.poll_next_unpin(tcx) {
            Poll::Ready(Some(event)) => event,
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
                    swarm.send_response(response, request_id).unwrap();
                }
                _ => {}
            },
            CommunicationEvent::ConnectPeer(addr) => connect_remote(swarm, addr, chan, topic.clone()),
            CommunicationEvent::Shutdown => {
                Swarm::remove_listener(&mut swarm, listener).unwrap();
                return Poll::Ready(());
            }
            _ => {}
        }
    }
    // Poll from the swarm for requests and responses from remote peers and publish them in the channel.
    loop {
        match swarm.poll_next_unpin(tcx) {
            Poll::Ready(Some(event)) => {
                println!("Received event: {:?}", event);
                if let P2PEvent::RequestResponse(boxed_event) = event {
                    chan.tell(
                        Publish {
                            msg: CommunicationEvent::Message(boxed_event.deref().clone()),
                            topic: topic.clone(),
                        },
                        None,
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
    swarm: &mut Swarm<P2PNetworkBehaviour<T, U>>,
    addr: Multiaddr,
    chan: &ChannelRef<CommunicationEvent<T, U>>,
    topic: Topic,
) {
    if Swarm::dial_addr(swarm, addr.clone()).is_ok() {
        loop {
            match task::block_on(swarm.next_event()) {
                SwarmEvent::Behaviour(P2PEvent::RequestResponse(boxed_event)) => {
                    chan.tell(
                        Publish {
                            msg: CommunicationEvent::Message(boxed_event.deref().clone()),
                            topic,
                        },
                        None,
                    );
                    break;
                }
                SwarmEvent::ConnectionEstablished {
                    peer_id: _,
                    endpoint: ConnectedPoint::Dialer { address },
                    num_established: _,
                } => {
                    if address == addr {
                        chan.tell(
                            Publish {
                                msg: CommunicationEvent::ConnectPeerResult { addr, result: Ok(()) },
                                topic,
                            },
                            None,
                        );
                        break;
                    }
                }
                SwarmEvent::UnreachableAddr {
                    peer_id: _,
                    address,
                    error,
                    attempts_remaining: 0,
                } => {
                    if address == addr {
                        chan.tell(
                            Publish {
                                msg: CommunicationEvent::ConnectPeerResult {
                                    addr,
                                    result: Err(ConnectPeerError::from(error)),
                                },
                                topic,
                            },
                            None,
                        );
                        break;
                    }
                }
                SwarmEvent::UnknownPeerUnreachableAddr { address, error } => {
                    if address == addr {
                        chan.tell(
                            Publish {
                                msg: CommunicationEvent::ConnectPeerResult {
                                    addr,
                                    result: Err(ConnectPeerError::from(error)),
                                },
                                topic,
                            },
                            None,
                        );
                        break;
                    }
                }
                _ => {}
            }
        }
    } else {
        chan.tell(
            Publish {
                msg: CommunicationEvent::ConnectPeerResult {
                    addr,
                    result: Err(ConnectPeerError::Transport),
                },
                topic,
            },
            None,
        );
    }
}

#[cfg(test)]
mod test {

    //     use super::*;
}
