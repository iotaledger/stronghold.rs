// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod ask;
pub mod message;
mod swarm_task;
use crate::behaviour::MessageEvent;
use async_std::task;
use core::task::{Context as TaskContext, Poll};
use futures::{
    channel::mpsc::{unbounded, UnboundedSender},
    future,
};
use libp2p::core::identity::Keypair;
use message::{CommunicationEvent, CommunicationRequest};
use riker::actors::*;
use swarm_task::SwarmTask;

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
/// use stronghold_communication::actor::{message::CommunicationEvent, CommunicationActor};
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
/// sys.actor_of_args::<CommunicationActor<Request, Response, Request>, _>(
///     "communication-actor",
///     (local_keys, sys.clone()),
/// );
/// ```
pub struct CommunicationActor<T: MessageEvent, U: MessageEvent, V: From<T> + Message> {
    swarm_tx: UnboundedSender<(CommunicationRequest<T, V>, Sender)>,
    swarm_task: Option<SwarmTask<T, U, V>>,
    poll_swarm_handle: Option<future::RemoteHandle<()>>,
}

impl<T: MessageEvent, U: MessageEvent, V: From<T> + Message> ActorFactoryArgs<(Keypair, ActorSystem)>
    for CommunicationActor<T, U, V>
{
    fn create_args((keypair, sys): (Keypair, ActorSystem)) -> Self {
        let (swarm_tx, swarm_rx) = unbounded();
        let swarm_task = SwarmTask::<T, U, V>::new(keypair, sys, swarm_rx);
        // Channel to communicate from the CommunicationActor with the swarm task.
        Self {
            swarm_tx,
            swarm_task: Some(swarm_task),
            poll_swarm_handle: None,
        }
    }
}

impl<T: MessageEvent, U: MessageEvent, V: From<T> + Message> Actor for CommunicationActor<T, U, V> {
    type Msg = CommunicationEvent<T, U, V>;

    fn post_start(&mut self, ctx: &Context<Self::Msg>) {
        // Kick off the swarm communication in it's own task.
        self.poll_swarm_handle = ctx.run(self.swarm_task.take().unwrap().poll_swarm()).ok();
    }

    // Forward the received events to the task that is managing the swarm communication.
    fn recv(&mut self, _ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        if let CommunicationEvent::Request(req) = msg {
            task::block_on(future::poll_fn(move |tx: &mut TaskContext<'_>| {
                match self.swarm_tx.poll_ready(tx) {
                    Poll::Ready(Ok(())) => Poll::Ready(self.swarm_tx.start_send((req.clone(), sender.clone()))),
                    Poll::Ready(err) => Poll::Ready(err),
                    Poll::Pending => Poll::Pending,
                }
            }))
            .unwrap();
        }
    }
}
// #[cfg(test)]
// mod test {
//
// use super::*;
// use core::time::Duration;
// use serde::{Deserialize, Serialize};
// use std::sync::{Arc, Mutex};
//
// use futures::{
// channel::oneshot::{channel, Sender as ChannelSender},
// future::RemoteHandle,
// FutureExt,
// };
//
// #[derive(Debug, Clone, Serialize, Deserialize)]
// enum Request {
// Ping,
// }
//
// #[derive(Debug, Clone, Serialize, Deserialize)]
// enum Response {
// Pong,
// }
//
// struct LocalActor {
// remote_peer: (PeerId, Multiaddr),
// has_received_response: bool,
// }
//
// impl ActorFactoryArgs<(PeerId, Multiaddr)> for LocalActor {
// fn create_args(remote_peer: (PeerId, Multiaddr)) -> Self {
// LocalActor {
// remote_peer,
// has_received_response: false,
// }
// }
// }
//
// impl Actor for LocalActor {
// type Msg = CommunicationEvent<Request, Response>;
//
// fn pre_start(&mut self, ctx: &Context<Self::Msg>) {
// let local_keys = Keypair::generate_ed25519();
// let self_ref = BasicActorRef::from(ctx.myself());
// let config = CommsActorConfig::new(local_keys, None, self_ref);
// ctx.actor_of_args::<CommunicationActor<Request, Response>, _>("communication", config)
// .unwrap();
// }
//
// fn post_start(&mut self, ctx: &Context<Self::Msg>) {
// let communication_actor = ctx.select("communication").unwrap();
// let event = CommunicationEvent::<Request, Response>::Request(CommunicationRequest::ConnectPeer {
// addr: self.remote_peer.1.clone(),
// peer_id: self.remote_peer.0,
// });
// communication_actor.try_tell(event, ctx.myself());
// }
//
// fn supervisor_strategy(&self) -> Strategy {
// Strategy::Escalate
// }
//
// fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, _sender: Sender) {
// if let CommunicationEvent::Response {
// request_id: _,
// result: _,
// } = msg
// {
// self.has_received_response = true;
// } else if let CommunicationEvent::ConnectPeerResult(result) = msg {
// let peer_id = result.expect("Panic due to no network connection");
// let request = CommunicationEvent::<Request, Response>::Request {
// peer_id,
// request_id: None,
// request: Request::Ping,
// };
// let communication_actor = ctx.select("*").unwrap();
// communication_actor.try_tell(request, ctx.myself());
// }
// }
//
// fn post_stop(&mut self) {
// assert!(self.has_received_response);
// }
// }
//
// struct RemoteActor {
// listening_addr: Multiaddr,
// }
//
// impl ActorFactoryArgs<Multiaddr> for RemoteActor {
// fn create_args(listening_addr: Multiaddr) -> Self {
// RemoteActor { listening_addr }
// }
// }
//
// impl Actor for RemoteActor {
// type Msg = CommunicationEvent<Request, Response>;
//
// fn pre_start(&mut self, ctx: &Context<Self::Msg>) {
// let local_keys = Keypair::generate_ed25519();
// let self_ref = BasicActorRef::from(ctx.myself());
// let config = CommsActorConfig::new(local_keys, Some(self.listening_addr.clone()), self_ref);
// ctx.actor_of_args::<CommunicationActor<Request, Response>, _>("communication", config)
// .unwrap();
// }
//
// fn supervisor_strategy(&self) -> Strategy {
// Strategy::Escalate
// }
//
// fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
// if let CommunicationEvent::Request {
// peer_id: _,
// request_id: Some(request_id),
// request: Request::Ping,
// } = msg
// {
// let response = CommunicationEvent::<Request, Response>::Response {
// request_id,
// result: Ok(Response::Pong),
// };
// sender.unwrap().try_tell(response, ctx.myself()).unwrap();
// }
// }
// }
//
// #[test]
// fn msg_external_actor() {
// let remote_addr: Multiaddr = "/ip4/127.0.0.1/tcp/8090".parse().unwrap();
//
// remote actor system
// let remote_sys = ActorSystem::new().unwrap();
// remote_sys
// .actor_of_args::<RemoteActor, _>("remote-actor", remote_addr.clone())
// .unwrap();
//
// local actor system
// let local_sys = ActorSystem::new().unwrap();
// local_sys
// .actor_of_args::<LocalActor, _>("local-actor", (PeerId::random(), remote_addr))
// .unwrap();
// std::thread::sleep(Duration::new(1, 0));
//
// task::block_on(async {
// remote_sys.shutdown().await.unwrap();
// local_sys.shutdown().await.unwrap();
// });
// }
//
// #[derive(Clone)]
// struct BlankActor;
//
// impl ActorFactory for BlankActor {
// fn create() -> Self {
// BlankActor
// }
// }
//
// impl Actor for BlankActor {
// type Msg = String;
//
// fn recv(&mut self, _ctx: &Context<Self::Msg>, _msg: Self::Msg, _sender: Sender) {}
// }
//
// #[test]
// fn ask_swarm_info() {
// let sys = ActorSystem::new().unwrap();
// let blank = sys.actor_of::<BlankActor>("blank").unwrap();
//
// let local_keys = crate::generate_new_keypair();
// let client_ref = BasicActorRef::from(blank);
// let addr: Multiaddr = "/ip4/127.0.0.1/tcp/8095".parse().unwrap();
// let config = CommsActorConfig::new(local_keys.clone(), Some(addr.clone()), client_ref);
// let communication_actor = sys
// .actor_of_args::<CommunicationActor<String, String>, _>("communication", config)
// .unwrap();
// let result = task::block_on(ask::<_, _, CommunicationEvent<String, String>, _>(
// &sys,
// &communication_actor,
// CommunicationEvent::GetSwarmInfo,
// ));
// match result {
// CommunicationEvent::SwarmInfo { peer_id, listeners } => {
// assert_eq!(PeerId::from(local_keys.public()), peer_id);
// assert!(listeners.contains(&addr));
// }
// _ => panic!(),
// }
// }
//
// #[derive(Clone)]
// struct TargetActor;
//
// impl ActorFactory for TargetActor {
// fn create() -> Self {
// TargetActor
// }
// }
//
// impl Actor for TargetActor {
// type Msg = CommunicationEvent<String, String>;
//
// fn recv(&mut self, _ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
// if let CommunicationEvent::Request {
// peer_id: _,
// request_id: Some(request_id),
// request,
// } = msg
// {
// let response = CommunicationEvent::<String, _>::Response {
// request_id,
// result: Ok(request),
// };
// sender.unwrap().try_tell(response, None).unwrap();
// } else {
// panic!();
// }
// }
// }
//
// #[test]
// fn ask_request() {
// start remote actor system
// let remote_sys = ActorSystem::new().unwrap();
// let target_actor = BasicActorRef::from(remote_sys.actor_of::<TargetActor>("target").unwrap());
// let remote_config = CommsActorConfig::new(crate::generate_new_keypair(), None, target_actor);
// let remote_comms = remote_sys
// .actor_of_args::<CommunicationActor<String, String>, _>("communication", remote_config)
// .unwrap();
//
// start local actor system
// let local_sys = ActorSystem::new().unwrap();
// let blank_actor = local_sys.actor_of::<BlankActor>("blank").unwrap();
// let local_config = CommsActorConfig::new(crate::generate_new_keypair(), None, BasicActorRef::from(blank_actor));
// let local_comms = local_sys
// .actor_of_args::<CommunicationActor<String, String>, _>("communication", local_config)
// .unwrap();
//
// std::thread::sleep(Duration::new(1, 0));
//
// obtain information about the remote peer id and listeners
// let result = task::block_on(ask::<_, _, CommunicationEvent<String, String>, _>(
// &remote_sys,
// &remote_comms,
// CommunicationEvent::GetSwarmInfo,
// ));
// let (remote_peer_id, listeners) = match result {
// CommunicationEvent::SwarmInfo { peer_id, listeners } => (peer_id, listeners),
// _ => panic!(),
// };
//
// connect remote peer
// match task::block_on(ask::<_, _, CommunicationEvent<String, String>, _>(
// &local_sys,
// &local_comms,
// CommunicationEvent::ConnectPeer {
// addr: listeners.last().unwrap().clone(),
// peer_id: remote_peer_id,
// },
// )) {
// CommunicationEvent::ConnectPeerResult(Ok(peer_id)) => assert_eq!(peer_id, remote_peer_id),
// _ => panic!(),
// };
//
// send message to remote peer
// let test_msg = String::from("test");
// match task::block_on(ask::<_, _, CommunicationEvent<String, String>, _>(
// &local_sys,
// &local_comms,
// CommunicationEvent::Request {
// peer_id: remote_peer_id,
// request_id: None,
// request: test_msg.clone(),
// },
// )) {
// CommunicationEvent::Response {
// request_id: _,
// result: Ok(echoed_msg),
// } => assert_eq!(test_msg, echoed_msg),
// _ => panic!(),
// };
// local_sys.stop(&local_comms);
// remote_sys.stop(&remote_comms);
// }
//
// fn ask<Msg, Ctx, R, T>(ctx: &Ctx, receiver: &T, msg: Msg) -> RemoteHandle<R>
// where
// Msg: Message,
// R: Message,
// Ctx: TmpActorRefFactory + Run,
// T: Tell<Msg>,
// {
// let (tx, rx) = channel::<R>();
// let tx = Arc::new(Mutex::new(Some(tx)));
//
// let props = Props::new_from_args(Box::new(AskActor::boxed), tx);
// let actor = ctx.tmp_actor_of_props(props).unwrap();
// receiver.tell(msg, Some(actor.into()));
//
// ctx.run(rx.map(|r| r.unwrap())).unwrap()
// }
//
// struct AskActor<Msg> {
// tx: Arc<Mutex<Option<ChannelSender<Msg>>>>,
// }
//
// impl<Msg: Message> AskActor<Msg> {
// fn boxed(tx: Arc<Mutex<Option<ChannelSender<Msg>>>>) -> BoxActor<Msg> {
// let ask = AskActor { tx };
// Box::new(ask)
// }
// }
//
// impl<Msg: Message> Actor for AskActor<Msg> {
// type Msg = Msg;
//
// fn recv(&mut self, ctx: &Context<Msg>, msg: Msg, _: Sender) {
// if let Ok(mut tx) = self.tx.lock() {
// tx.take().unwrap().send(msg).unwrap();
// }
// ctx.stop(&ctx.myself);
// }
// }
// }
