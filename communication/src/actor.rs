// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod ask;
pub mod message;
mod swarm_task;
use crate::behaviour::MessageEvent;
use async_std::task;
use core::{
    marker::PhantomData,
    task::{Context as TaskContext, Poll},
};
use futures::{
    channel::mpsc::{unbounded, UnboundedSender},
    future,
};
use libp2p::core::identity::Keypair;
use message::{CommunicationRequest, FirewallRequest};
use riker::actors::*;
use swarm_task::SwarmTask;

#[derive(Debug, Clone)]
pub struct CommunicationConfig<Req, T, U>
where
    Req: MessageEvent,
    T: Message + From<Req>,
    U: Message + From<FirewallRequest<Req>>,
{
    system: ActorSystem,
    client: ActorRef<T>,
    firewall: ActorRef<U>,
    marker: PhantomData<Req>,
}

impl<Req, T, U> CommunicationConfig<Req, T, U>
where
    Req: MessageEvent,
    T: Message + From<Req>,
    U: Message + From<FirewallRequest<Req>>,
{
    pub fn new(system: ActorSystem, client: ActorRef<T>, firewall: ActorRef<U>) -> Self {
        CommunicationConfig {
            system,
            client,
            firewall,
            marker: PhantomData,
        }
    }
}

/// Actor for the communication to a remote peer over the swarm.
///
/// Publishes incoming request- and response-messages from the swarm to a channel and/ or a client
/// actor, depending on the [`CommsActorConfig`].
/// Received [`CommunicationActorMsg::Message`]s are send to the associated Peer.
///
///
/// ```no_run
/// use libp2p::identity::Keypair;
/// use riker::actors::*;
/// use serde::{Deserialize, Serialize};
/// use stronghold_communication::actor::{message::CommunicationActorMsg, CommunicationActor};
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
pub struct CommunicationActor<Req, Res, T, U>
where
    Req: MessageEvent,
    Res: MessageEvent,
    T: Message + From<Req>,
    U: Message + From<FirewallRequest<Req>>,
{
    swarm_tx: UnboundedSender<(CommunicationRequest<Req, T>, Sender)>,
    swarm_task: Option<SwarmTask<Req, Res, T, U>>,
    poll_swarm_handle: Option<future::RemoteHandle<()>>,
}

impl<Req, Res, T, U> ActorFactoryArgs<(Keypair, CommunicationConfig<Req, T, U>)> for CommunicationActor<Req, Res, T, U>
where
    Req: MessageEvent,
    Res: MessageEvent,
    T: Message + From<Req>,
    U: Message + From<FirewallRequest<Req>>,
{
    fn create_args((keypair, config): (Keypair, CommunicationConfig<Req, T, U>)) -> Self {
        let (swarm_tx, swarm_rx) = unbounded();
        let swarm_task = SwarmTask::<_, Res, _, _>::new(keypair, config, swarm_rx);
        // Channel to communicate from the CommunicationActor with the swarm task.
        Self {
            swarm_tx,
            swarm_task: Some(swarm_task),
            poll_swarm_handle: None,
        }
    }
}

impl<Req, Res, T, U> Actor for CommunicationActor<Req, Res, T, U>
where
    Req: MessageEvent,
    Res: MessageEvent,
    T: Message + From<Req>,
    U: Message + From<FirewallRequest<Req>>,
{
    type Msg = CommunicationRequest<Req, T>;

    fn post_start(&mut self, ctx: &Context<Self::Msg>) {
        // Kick off the swarm communication in it's own task.
        let task: SwarmTask<Req, Res, T, U> = self.swarm_task.take().unwrap();
        self.poll_swarm_handle = ctx.run(task.poll_swarm()).ok();
    }

    // Forward the received events to the task that is managing the swarm communication.
    fn recv(&mut self, _ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        task::block_on(future::poll_fn(move |tx: &mut TaskContext<'_>| {
            match self.swarm_tx.poll_ready(tx) {
                Poll::Ready(Ok(())) => Poll::Ready(self.swarm_tx.start_send((msg.clone(), sender.clone()))),
                Poll::Ready(err) => Poll::Ready(err),
                Poll::Pending => Poll::Pending,
            }
        }))
        .unwrap();
    }

    fn supervisor_strategy(&self) -> Strategy {
        Strategy::Escalate
    }
}

#[cfg(test)]
mod test {

    use super::{ask::ask, message::*, *};
    use core::time::Duration;
    use libp2p::{Multiaddr, PeerId};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone)]
    struct Firewall<Req: Message> {
        marker: PhantomData<Req>,
    }

    impl<Req: Message> Default for Firewall<Req> {
        fn default() -> Self {
            Firewall { marker: PhantomData }
        }
    }

    impl<Req: Message> Actor for Firewall<Req> {
        type Msg = FirewallRequest<Req>;

        fn recv(&mut self, _ctx: &Context<Self::Msg>, _msg: FirewallRequest<Req>, sender: Sender) {
            sender.unwrap().try_tell(FirewallResponse::Accept, None).unwrap()
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum Request {
        Ping,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum Response {
        Pong,
    }

    #[actor(Request, CommunicationResults<Response>)]
    #[derive(Debug, Clone)]
    struct LocalActor {
        remote_peer: PeerId,
        remote_addr: Multiaddr,
        has_received_response: bool,
    }

    impl ActorFactoryArgs<(PeerId, Multiaddr)> for LocalActor {
        fn create_args((remote_peer, remote_addr): (PeerId, Multiaddr)) -> Self {
            LocalActor {
                remote_peer,
                remote_addr,
                has_received_response: false,
            }
        }
    }

    impl Actor for LocalActor {
        type Msg = LocalActorMsg;

        fn post_start(&mut self, ctx: &Context<Self::Msg>) {
            let req = CommunicationRequest::<Request, LocalActorMsg>::ConnectPeer {
                addr: self.remote_addr.clone(),
                peer_id: self.remote_peer,
            };
            let communication_actor = ctx.select("communication").unwrap();
            communication_actor.try_tell(req, ctx.myself());
        }

        fn supervisor_strategy(&self) -> Strategy {
            Strategy::Escalate
        }

        fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
            self.receive(ctx, msg, sender);
        }

        fn post_stop(&mut self) {
            assert!(self.has_received_response);
        }
    }

    impl Receive<Request> for LocalActor {
        type Msg = LocalActorMsg;

        fn receive(&mut self, _ctx: &Context<Self::Msg>, _msg: Request, _sender: Sender) {}
    }

    impl Receive<CommunicationResults<Response>> for LocalActor {
        type Msg = LocalActorMsg;

        fn receive(&mut self, ctx: &Context<Self::Msg>, msg: CommunicationResults<Response>, _sender: Sender) {
            if let CommunicationResults::RequestMsgResult(Ok(_)) = msg {
                self.has_received_response = true;
            } else if let CommunicationResults::ConnectPeerResult(result) = msg {
                let peer_id = result.expect("Panic due to no network connection");
                let req = CommunicationRequest::<Request, LocalActorMsg>::RequestMsg {
                    peer_id,
                    request: Request::Ping,
                };
                let communication_actor = ctx.select("communication").unwrap();
                communication_actor.try_tell(req, ctx.myself());
            }
        }
    }

    #[derive(Debug, Clone)]
    struct RemoteActor {
        listening_addr: Multiaddr,
    }

    impl ActorFactoryArgs<Multiaddr> for RemoteActor {
        fn create_args(listening_addr: Multiaddr) -> Self {
            RemoteActor { listening_addr }
        }
    }

    impl Actor for RemoteActor {
        type Msg = Request;

        fn post_start(&mut self, ctx: &Context<Self::Msg>) {
            let req = CommunicationRequest::<Request, Request>::StartListening(Some(self.listening_addr.clone()));
            let communication_actor = ctx.select("communication").unwrap();
            communication_actor.try_tell(req, ctx.myself());
        }

        fn supervisor_strategy(&self) -> Strategy {
            Strategy::Escalate
        }

        fn recv(&mut self, _ctx: &Context<Self::Msg>, _msg: Self::Msg, sender: Sender) {
            let response = Response::Pong;
            sender.unwrap().try_tell(response, None).unwrap();
        }
    }

    #[test]
    fn msg_external_actor() {
        let remote_addr: Multiaddr = "/ip4/127.0.0.1/tcp/8090".parse().unwrap();

        // remote actor system
        let remote_sys = ActorSystem::new().unwrap();
        let keys = Keypair::generate_ed25519();
        let client = remote_sys
            .actor_of_args::<RemoteActor, _>("remote-actor", remote_addr.clone())
            .unwrap();
        let firewall = remote_sys.actor_of::<Firewall<Request>>("firewall").unwrap();
        let config = CommunicationConfig::new(remote_sys.clone(), client, firewall);
        remote_sys
            .actor_of_args::<CommunicationActor<_, Response, _, _>, _>("communication", (keys, config))
            .unwrap();

        // local actor system
        let local_sys = ActorSystem::new().unwrap();
        let keys = Keypair::generate_ed25519();
        let client = local_sys
            .actor_of_args::<LocalActor, _>("local-actor", (PeerId::random(), remote_addr))
            .unwrap();
        let firewall = local_sys.actor_of::<Firewall<Request>>("firewall").unwrap();
        let config = CommunicationConfig::new(local_sys.clone(), client, firewall);
        local_sys
            .actor_of_args::<CommunicationActor<_, Response, _, _>, _>("communication", (keys, config))
            .unwrap();
        std::thread::sleep(Duration::new(1, 0));

        task::block_on(async {
            remote_sys.shutdown().await.unwrap();
            local_sys.shutdown().await.unwrap();
        });
    }

    #[derive(Clone, Debug)]
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
        let client = sys.actor_of::<BlankActor>("blank").unwrap();

        let firewall = sys.actor_of::<Firewall<String>>("firewall").unwrap();
        let keys = crate::generate_new_keypair();
        let config = CommunicationConfig::new(sys.clone(), client, firewall);
        let communication_actor = sys
            .actor_of_args::<CommunicationActor<_, String, _, _>, _>("communication", (keys.clone(), config))
            .unwrap();

        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/8095".parse().unwrap();
        match task::block_on(ask(
            &sys,
            &communication_actor,
            CommunicationRequest::StartListening(Some(addr.clone())),
        )) {
            CommunicationResults::<String>::StartListeningResult(actual_addr) => assert_eq!(addr, actual_addr.unwrap()),
            _ => panic!(),
        }

        let result = task::block_on(ask(&sys, &communication_actor, CommunicationRequest::GetSwarmInfo));
        match result {
            CommunicationResults::<String>::SwarmInfo { peer_id, listeners } => {
                assert_eq!(PeerId::from(keys.public()), peer_id);
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
        type Msg = String;

        fn recv(&mut self, _ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
            // echo msg back
            sender.unwrap().try_tell(msg, None).unwrap();
        }
    }

    #[test]
    fn ask_request() {
        // start remote actor system
        let remote_sys = ActorSystem::new().unwrap();
        let target_actor = remote_sys.actor_of::<TargetActor>("target").unwrap();
        let firewall = remote_sys.actor_of::<Firewall<String>>("firewall").unwrap();
        let keys = crate::generate_new_keypair();
        let config = CommunicationConfig::new(remote_sys.clone(), target_actor, firewall);
        let remote_comms = remote_sys
            .actor_of_args::<CommunicationActor<_, String, _, _>, _>("communication", (keys, config))
            .unwrap();
        match task::block_on(ask(
            &remote_sys,
            &remote_comms,
            CommunicationRequest::StartListening(None),
        )) {
            CommunicationResults::<String>::StartListeningResult(a) => {
                a.unwrap();
            }
            _ => panic!(),
        }

        // start local actor system
        let local_sys = ActorSystem::new().unwrap();
        let blank_actor = local_sys.actor_of::<BlankActor>("blank").unwrap();
        let firewall = remote_sys.actor_of::<Firewall<String>>("firewall").unwrap();
        let keys = crate::generate_new_keypair();
        let config = CommunicationConfig::new(local_sys.clone(), blank_actor, firewall);
        let local_comms = local_sys
            .actor_of_args::<CommunicationActor<_, String, _, _>, _>("communication", (keys, config))
            .unwrap();

        std::thread::sleep(Duration::new(1, 0));
        // obtain information about the remote peer id and listeners
        let (remote_peer_id, listeners) =
            match task::block_on(ask(&remote_sys, &remote_comms, CommunicationRequest::GetSwarmInfo)) {
                CommunicationResults::<String>::SwarmInfo { peer_id, listeners } => (peer_id, listeners),
                _ => panic!(),
            };
        // connect remote peer
        match task::block_on(ask(
            &local_sys,
            &local_comms,
            CommunicationRequest::ConnectPeer {
                addr: listeners.last().unwrap().clone(),
                peer_id: remote_peer_id,
            },
        )) {
            CommunicationResults::<String>::ConnectPeerResult(Ok(peer_id)) => assert_eq!(peer_id, remote_peer_id),
            _ => panic!(),
        };

        // send message to remote peer
        let test_msg = String::from("test");
        match task::block_on(ask(
            &local_sys,
            &local_comms,
            CommunicationRequest::RequestMsg {
                peer_id: remote_peer_id,
                request: test_msg.clone(),
            },
        )) {
            CommunicationResults::<String>::RequestMsgResult(Ok(echoed_msg)) => assert_eq!(test_msg, echoed_msg),
            _ => panic!(),
        };
        local_sys.stop(&local_comms);
        remote_sys.stop(&remote_comms);
    }
}
