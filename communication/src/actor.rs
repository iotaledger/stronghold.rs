// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod ask;
mod connections;
pub mod firewall;
mod swarm_task;
mod types;
use crate::behaviour::{BehaviourConfig, MessageEvent};
pub use ask::ask;
use async_std::task;
use core::{
    marker::PhantomData,
    task::{Context as TaskContext, Poll},
};
use firewall::*;
use futures::{
    channel::mpsc::{unbounded, UnboundedSender},
    future,
};
use libp2p::identity::Keypair;
use riker::actors::*;
use swarm_task::SwarmTask;
pub use types::*;

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
/// use stronghold_communication::{
///     actor::{firewall::OpenFirewall, CommunicationActor, CommunicationConfig},
///     behaviour::BehaviourConfig,
/// };
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
/// let firewall = sys.actor_of::<OpenFirewall<Request>>("firewall").unwrap();
/// let client = sys.actor_of::<ClientActor>("client").unwrap();
/// let actor_config = CommunicationConfig::new(client, firewall);
/// let behaviour_config = BehaviourConfig::default();
/// let comms_actor = sys
///     .actor_of_args::<CommunicationActor<_, Response, _, _>, _>(
///         "communication",
///         (local_keys, actor_config, behaviour_config),
///     )
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
    swarm_task_config: Option<(Keypair, CommunicationConfig<Req, T, U>, BehaviourConfig)>,
    poll_swarm_handle: Option<future::RemoteHandle<()>>,
    marker: PhantomData<Res>,
}

impl<Req, Res, T, U> ActorFactoryArgs<(Keypair, CommunicationConfig<Req, T, U>, BehaviourConfig)>
    for CommunicationActor<Req, Res, T, U>
where
    Req: MessageEvent,
    Res: MessageEvent,
    T: Message + From<Req>,
    U: Message + From<FirewallRequest<Req>>,
{
    // Create a [`CommunicationActor`] that spwans a task to poll from the swarm.
    // The provided keypair is used to authenticate the swarm communication.
    fn create_args(config: (Keypair, CommunicationConfig<Req, T, U>, BehaviourConfig)) -> Self {
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
    // The swarm task won't start listening to the swarm untill a [`CommunicationRequest::StartListening`] was sent to
    // it.
    fn post_start(&mut self, ctx: &Context<Self::Msg>) {
        let (swarm_tx, swarm_rx) = unbounded();
        self.swarm_tx = Some(swarm_tx);
        // Init task
        let (keypair, actor_config, behaviour_config) = self.swarm_task_config.take().unwrap();
        let actor_system = ctx.system.clone();
        let swarm_task =
            SwarmTask::<_, Res, _, _>::new(actor_system, keypair, actor_config, behaviour_config, swarm_rx);
        // Kick off the swarm communication.
        self.poll_swarm_handle = ctx.run(swarm_task.poll_swarm()).ok();
    }

    // Forward the received events to the task that is managing the swarm communication.
    fn recv(&mut self, _ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        self.send_swarm_task(msg, sender);
    }

    fn post_stop(&mut self) {
        self.send_swarm_task(CommunicationRequest::Shutdown, None);
        task::block_on(self.poll_swarm_handle.take().unwrap());
        self.swarm_tx.take().unwrap().disconnect();
    }
}

impl<Req, Res, T, U> CommunicationActor<Req, Res, T, U>
where
    Req: MessageEvent,
    Res: MessageEvent,
    T: Message + From<Req>,
    U: Message + From<FirewallRequest<Req>>,
{
    fn send_swarm_task(&mut self, msg: CommunicationRequest<Req, T>, sender: Sender) {
        let mut tx = self.swarm_tx.clone().unwrap();
        task::block_on(future::poll_fn(move |tcx: &mut TaskContext<'_>| {
            match tx.poll_ready(tcx) {
                Poll::Ready(Ok(())) => Poll::Ready(tx.start_send((msg.clone(), sender.clone()))),
                Poll::Ready(err) => Poll::Ready(err),
                Poll::Pending => Poll::Pending,
            }
        }))
        .unwrap()
    }
}
