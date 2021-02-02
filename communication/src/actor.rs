// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod ask;
mod message;
mod swarm_task;
use crate::behaviour::MessageEvent;
pub use ask::ask;
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
pub use message::*;
use riker::actors::*;
use swarm_task::SwarmTask;

#[derive(Debug, Clone)]
/// The actor configuration
pub struct CommunicationConfig<Req, T, U>
where
    Req: MessageEvent,
    T: Message + From<Req>,
    U: Message + From<FirewallRequest<Req>>,
{
    /// target client for incoming request
    pub client: ActorRef<T>,
    /// The firewall actor.
    ///
    /// For any request, a [`FirewallRequest`] is sent to that actor and the request will be reject unless a
    /// FirewallRequest::Accept is return from the firewall,
    pub firewall: ActorRef<U>,
    marker: PhantomData<Req>,
}

impl<Req, T, U> CommunicationConfig<Req, T, U>
where
    Req: MessageEvent,
    T: Message + From<Req>,
    U: Message + From<FirewallRequest<Req>>,
{
    pub fn new(client: ActorRef<T>, firewall: ActorRef<U>) -> Self {
        CommunicationConfig {
            client,
            firewall,
            marker: PhantomData,
        }
    }
}

/// Actor for the communication to a remote peer over the swarm.
///
/// Sends the [`CommunicationRequest`]s it receives over the swarm to the corresponding remote peer and forwards
/// incoming request to the client provided in the [`CommunicationConfig`]. Before forwarding any requests, a
/// FirewallRequest is send to the firewall and the Request will only be forwarded if a FirewallResponse::Accept was
/// returned.
///
/// If remote peers should be able to dial the local system, a [`CommunicationRequest::StartListening`] has to be sent
/// to the [`CommunicationActor`].
///
/// ```no_run
/// use libp2p::identity::Keypair;
/// use riker::actors::*;
/// use serde::{Deserialize, Serialize};
/// use stronghold_communication::actor::{CommunicationActor, CommunicationConfig, FirewallRequest, FirewallResponse};
///
/// #[derive(Debug, Clone, Serialize, Deserialize)]
/// pub enum Request {
///     Ping,
/// }
///
/// #[derive(Debug, Clone, Serialize, Deserialize)]
/// pub enum Response {
///     Pong,
/// }
/// // Dummy firewall that approves all requests
/// #[derive(Debug, Clone)]
/// struct Firewall;
///
/// impl ActorFactory for Firewall {
///     fn create() -> Self {
///         Firewall
///     }
/// }
///
/// impl Actor for Firewall {
///     type Msg = FirewallRequest<Request>;
///
///     fn recv(&mut self, _ctx: &Context<Self::Msg>, _msg: Self::Msg, sender: Sender) {
///         sender.unwrap().try_tell(FirewallResponse::Accept, None).unwrap()
///     }
/// }
///
/// // blank client actor without any logic
/// #[derive(Clone, Debug)]
/// struct ClientActor;
///
/// impl ActorFactory for ClientActor {
///     fn create() -> Self {
///         ClientActor
///     }
/// }
///
/// impl Actor for ClientActor {
///     type Msg = Request;
///
///     fn recv(&mut self, _ctx: &Context<Self::Msg>, _msg: Self::Msg, sender: Sender) {}
/// }
///
/// let local_keys = Keypair::generate_ed25519();
/// let sys = ActorSystem::new().unwrap();
/// let keys = Keypair::generate_ed25519();
/// let firewall = sys.actor_of::<Firewall>("firewall").unwrap();
/// let client = sys.actor_of::<ClientActor>("client").unwrap();
/// let config = CommunicationConfig::new(client, firewall);
/// let comms_actor = sys
///     .actor_of_args::<CommunicationActor<_, Response, _, _>, _>("communication", (local_keys, config))
///     .unwrap();
/// ```
pub struct CommunicationActor<Req, Res, T, U>
where
    Req: MessageEvent,
    Res: MessageEvent,
    T: Message + From<Req>,
    U: Message + From<FirewallRequest<Req>>,
{
    swarm_tx: Option<UnboundedSender<(CommunicationRequest<Req, T>, Sender)>>,
    swarm_task_config: Option<(Keypair, CommunicationConfig<Req, T, U>)>,
    poll_swarm_handle: Option<future::RemoteHandle<()>>,
    marker: PhantomData<Res>,
}

impl<Req, Res, T, U> ActorFactoryArgs<(Keypair, CommunicationConfig<Req, T, U>)> for CommunicationActor<Req, Res, T, U>
where
    Req: MessageEvent,
    Res: MessageEvent,
    T: Message + From<Req>,
    U: Message + From<FirewallRequest<Req>>,
{
    // Create a [`CommunicationActor`] that spwans a task to poll from the swarm.
    // The provided keypair is used to authenticate the swarm communication.
    fn create_args(config: (Keypair, CommunicationConfig<Req, T, U>)) -> Self {
        Self {
            swarm_tx: None,
            swarm_task_config: Some(config),
            poll_swarm_handle: None,
            marker: PhantomData,
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

    // Spawn a task for polling the swarm and forwarding messages from/to remote peers.
    // A channel is created to send the messages that the [`CommunicationActor`] receives to that task.
    // The swarm task won't start listening to the swarm untill a [`CommuncationRequest::StartListening`] was sent to
    // it.
    fn post_start(&mut self, ctx: &Context<Self::Msg>) {
        let (swarm_tx, swarm_rx) = unbounded();
        self.swarm_tx = Some(swarm_tx);
        // Init task
        let (keypair, config) = self.swarm_task_config.take().unwrap();
        let actor_system = ctx.system.clone();
        let swarm_task = SwarmTask::<_, Res, _, _>::new(actor_system, keypair, config, swarm_rx);
        // Kick off the swarm communication.
        self.poll_swarm_handle = ctx.run(swarm_task.poll_swarm()).ok();
    }

    // Forward the received events to the task that is managing the swarm communication.
    fn recv(&mut self, _ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        let mut tx = self.swarm_tx.clone().unwrap();
        task::block_on(future::poll_fn(move |tcx: &mut TaskContext<'_>| {
            match tx.poll_ready(tcx) {
                Poll::Ready(Ok(())) => Poll::Ready(tx.start_send((msg.clone(), sender.clone()))),
                Poll::Ready(err) => Poll::Ready(err),
                Poll::Pending => Poll::Pending,
            }
        }))
        .unwrap();
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use core::time::Duration;
    use libp2p::{Multiaddr, PeerId};
    use serde::{Deserialize, Serialize};

    // the type of the send request and reponse messages
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum Request {
        Ping,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub enum Response {
        Pong,
    }

    // Dummy firewall that approves all requests
    #[derive(Debug, Clone)]
    struct Firewall;

    impl ActorFactory for Firewall {
        fn create() -> Self {
            Firewall
        }
    }

    impl Actor for Firewall {
        type Msg = FirewallRequest<Request>;

        fn recv(&mut self, _ctx: &Context<Self::Msg>, _msg: Self::Msg, sender: Sender) {
            sender.unwrap().try_tell(FirewallResponse::Accept, None).unwrap()
        }
    }

    // blank client actor without any logic
    #[derive(Clone, Debug)]
    struct BlankActor;

    impl ActorFactory for BlankActor {
        fn create() -> Self {
            BlankActor
        }
    }

    impl Actor for BlankActor {
        type Msg = Request;

        fn post_start(&mut self, ctx: &Context<Self::Msg>) {
            ctx.stop(&ctx.myself);
        }

        fn recv(&mut self, _ctx: &Context<Self::Msg>, _msg: Self::Msg, _sender: Sender) {}
    }

    fn init_system(
        sys: &ActorSystem,
        client: ActorRef<Request>,
    ) -> (PeerId, ActorRef<CommunicationRequest<Request, Request>>) {
        // init remote actor system
        let keys = Keypair::generate_ed25519();
        let peer_id = PeerId::from(keys.public());
        let firewall = sys.actor_of::<Firewall>("firewall").unwrap();
        let config = CommunicationConfig::new(client, firewall);
        let comms_actor = sys
            .actor_of_args::<CommunicationActor<_, Response, _, _>, _>("communication", (keys, config))
            .unwrap();
        (peer_id, comms_actor)
    }

    // ====== First test ==========================

    // local actor that receives the results for outgoing requests
    #[derive(Debug, Clone)]
    struct LocalActor;

    impl ActorFactory for LocalActor {
        fn create() -> Self {
            LocalActor
        }
    }

    impl Actor for LocalActor {
        type Msg = CommunicationResults<Response>;

        fn supervisor_strategy(&self) -> Strategy {
            Strategy::Stop
        }

        fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, _sender: Sender) {
            if let CommunicationResults::RequestMsgResult(Ok(_)) = msg {
                ctx.stop(&ctx.myself);
            } else if let CommunicationResults::ConnectPeerResult(result) = msg {
                let peer_id = result.expect("Panic due to no network connection");
                let req = CommunicationRequest::<Request, Request>::RequestMsg {
                    peer_id,
                    request: Request::Ping,
                };
                let communication_actor = ctx.select("/user/communication").unwrap();
                communication_actor.try_tell(req, ctx.myself());
            }
        }
    }

    // remote actor that responds to a requests from the local system
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

        fn recv(&mut self, _ctx: &Context<Self::Msg>, _msg: Self::Msg, sender: Sender) {
            let response = Response::Pong;
            sender.unwrap().try_tell(response, None).unwrap();
        }
    }

    #[test]
    fn msg_external_actor() {
        let remote_addr: Multiaddr = "/ip4/127.0.0.1/tcp/8090".parse().unwrap();

        // init remote actor system
        let remote_sys = ActorSystem::new().unwrap();
        let client = remote_sys
            .actor_of_args::<RemoteActor, _>("remote-actor", remote_addr.clone())
            .unwrap();
        let (remote_peer_id, remote_comms) = init_system(&remote_sys, client);
        // remote comms start listening on the port
        let req = CommunicationRequest::<Request, Request>::StartListening(Some(remote_addr.clone()));
        remote_comms.tell(req, None);

        // local actor system
        let local_sys = ActorSystem::new().unwrap();
        let client = local_sys.actor_of::<BlankActor>("blank").unwrap();
        let (_, local_comms) = init_system(&local_sys, client);

        let local_actor = local_sys.actor_of::<LocalActor>("local-actor").unwrap();

        std::thread::sleep(Duration::new(1, 0));

        // send request, use local_actor as target for the response
        let req = CommunicationRequest::<Request, Request>::ConnectPeer {
            addr: remote_addr,
            peer_id: remote_peer_id,
        };
        local_comms.tell(req, local_actor.clone().into());

        while local_sys
            .user_root()
            .children()
            .any(|actor| actor == local_actor.clone().into())
        {
            // in order to lower cpu usage, sleep here
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    // ====== Second test ==========================

    #[test]
    fn ask_swarm_info() {
        let sys = ActorSystem::new().unwrap();
        let client = sys.actor_of::<BlankActor>("blank").unwrap();
        let keys = Keypair::generate_ed25519();
        let firewall = sys.actor_of::<Firewall>("firewall").unwrap();
        let config = CommunicationConfig::new(client, firewall);
        let communication_actor = sys
            .actor_of_args::<CommunicationActor<_, Response, _, _>, _>("communication", (keys.clone(), config))
            .unwrap();

        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/8095".parse().unwrap();
        match task::block_on(ask(
            &sys,
            &communication_actor,
            CommunicationRequest::StartListening(Some(addr.clone())),
        )) {
            CommunicationResults::<Response>::StartListeningResult(actual_addr) => {
                assert_eq!(addr, actual_addr.unwrap())
            }
            _ => panic!(),
        }

        let result = task::block_on(ask(&sys, &communication_actor, CommunicationRequest::GetSwarmInfo));
        match result {
            CommunicationResults::<Response>::SwarmInfo { peer_id, listeners } => {
                assert_eq!(PeerId::from(keys.public()), peer_id);
                assert!(listeners.contains(&addr));
            }
            _ => panic!(),
        }
    }

    // ====== Third test ==========================

    #[derive(Clone)]
    struct TargetActor;

    impl ActorFactory for TargetActor {
        fn create() -> Self {
            TargetActor
        }
    }

    impl Actor for TargetActor {
        type Msg = Request;

        fn recv(&mut self, _ctx: &Context<Self::Msg>, _msg: Self::Msg, sender: Sender) {
            // echo msg back
            sender.unwrap().try_tell(Response::Pong, None).unwrap();
        }
    }

    #[test]
    fn ask_request() {
        // start remote actor system
        let remote_sys = ActorSystem::new().unwrap();
        let target_actor = remote_sys.actor_of::<TargetActor>("target").unwrap();
        let (_, remote_comms) = init_system(&remote_sys, target_actor);
        match task::block_on(ask(
            &remote_sys,
            &remote_comms,
            CommunicationRequest::StartListening(None),
        )) {
            CommunicationResults::<Response>::StartListeningResult(a) => {
                a.unwrap();
            }
            _ => panic!(),
        }

        // start local actor system
        let local_sys = ActorSystem::new().unwrap();
        let blank_actor = local_sys.actor_of::<BlankActor>("blank").unwrap();
        let (_, local_comms) = init_system(&local_sys, blank_actor);

        std::thread::sleep(Duration::new(1, 0));
        // obtain information about the remote peer id and listeners
        let (remote_peer_id, listeners) =
            match task::block_on(ask(&remote_sys, &remote_comms, CommunicationRequest::GetSwarmInfo)) {
                CommunicationResults::<Response>::SwarmInfo { peer_id, listeners } => (peer_id, listeners),
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
            CommunicationResults::<Response>::ConnectPeerResult(Ok(peer_id)) => assert_eq!(peer_id, remote_peer_id),
            _ => panic!(),
        };

        // send message to remote peer
        match task::block_on(ask(
            &local_sys,
            &local_comms,
            CommunicationRequest::RequestMsg {
                peer_id: remote_peer_id,
                request: Request::Ping,
            },
        )) {
            CommunicationResults::<Response>::RequestMsgResult(Ok(res)) => assert_eq!(res, Response::Pong),
            _ => panic!(),
        };
        local_sys.stop(&local_comms);
        remote_sys.stop(&remote_comms);
    }
}
