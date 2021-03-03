// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod connections;
pub mod firewall;
mod swarm_task;
mod types;
use crate::behaviour::{BehaviourConfig, MessageEvent};
use async_std::task;
use core::{
    marker::PhantomData,
    task::{Context as TaskContext, Poll},
};
use firewall::*;
use futures::{
    channel::mpsc::{unbounded, SendError, UnboundedSender},
    future,
};
use libp2p::identity::Keypair;
use riker::actors::*;
use stronghold_utils::ask;
use swarm_task::SwarmTask;
pub use types::*;

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
/// use communication_macros::RequestPermissions;
/// use libp2p::identity::Keypair;
/// use riker::actors::*;
/// use serde::{Deserialize, Serialize};
/// use stronghold_communication::{
///     actor::{
///         firewall::{PermissionSum, ToPermissionVariants, VariantPermission},
///         CommunicationActor,
///     },
///     behaviour::BehaviourConfig,
/// };
///
/// #[derive(Debug, Clone, Serialize, Deserialize, RequestPermissions)]
/// pub enum Request {
///     Ping,
/// }
///
/// #[derive(Debug, Clone, Serialize, Deserialize, RequestPermissions)]
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
/// let sys = ActorSystem::new().expect("Init actor system failed.");
/// let keys = Keypair::generate_ed25519();
/// let client = sys
///     .actor_of::<ClientActor>("client")
///     .expect("Init client actor failed.");
/// let behaviour_config = BehaviourConfig::default();
/// let comms_actor = sys
///     .actor_of_args::<CommunicationActor<Request, Response, _>, _>(
///         "communication",
///         (local_keys, client, behaviour_config),
///     )
///     .expect("Init communication actor failed.");
/// ```
pub struct CommunicationActor<Req, Res, ClientMsg>
where
    Req: MessageEvent + VariantPermission + Into<ClientMsg>,
    Res: MessageEvent,
    ClientMsg: Message,
{
    // Channel for messages to the swarm task.
    swarm_tx: Option<UnboundedSender<(CommunicationRequest<Req, ClientMsg>, Sender)>>,
    swarm_task_config: Option<(Keypair, ActorRef<ClientMsg>, BehaviourConfig)>,
    // Handle of the running swarm task.
    poll_swarm_handle: Option<future::RemoteHandle<()>>,
    marker: PhantomData<Res>,
}

impl<Req, Res, ClientMsg> ActorFactoryArgs<(Keypair, ActorRef<ClientMsg>, BehaviourConfig)>
    for CommunicationActor<Req, Res, ClientMsg>
where
    Req: MessageEvent + VariantPermission + Into<ClientMsg>,
    Res: MessageEvent,
    ClientMsg: Message,
{
    // Create a [`CommunicationActor`] that spwans a task to poll from the swarm.
    // The provided keypair is used to authenticate the swarm communication.
    fn create_args(config: (Keypair, ActorRef<ClientMsg>, BehaviourConfig)) -> Self {
        Self {
            swarm_tx: None,
            swarm_task_config: Some(config),
            poll_swarm_handle: None,
            marker: PhantomData,
        }
    }
}

impl<Req, Res, ClientMsg> Actor for CommunicationActor<Req, Res, ClientMsg>
where
    Req: MessageEvent + VariantPermission + Into<ClientMsg>,
    Res: MessageEvent,
    ClientMsg: Message,
{
    type Msg = CommunicationRequest<Req, ClientMsg>;

    // Spawn a task for polling the swarm and forwarding messages from/to remote peers.
    // A channel is created to send the messages that the [`CommunicationActor`] receives to that task.
    // The swarm task won't start listening to the swarm untill a [`CommunicationRequest::StartListening`] was sent to
    // it.
    fn post_start(&mut self, ctx: &Context<Self::Msg>) {
        // Init task
        if let Some((keypair, client, behaviour_config)) = self.swarm_task_config.take() {
            let (swarm_tx, swarm_rx) = unbounded();
            self.swarm_tx = Some(swarm_tx);

            let actor_system = ctx.system.clone();
            let swarm_task = SwarmTask::<_, Res, _>::new(actor_system, keypair, client, behaviour_config, swarm_rx);
            if let Ok(swarm_task) = swarm_task {
                // Kick off the swarm communication.
                self.poll_swarm_handle = ctx.run(swarm_task.poll_swarm()).ok();
            } else {
                // Init network behaviour failed, shutdown actor.
                ctx.stop(ctx.myself());
            }
        }
    }

    // Shutdown the swarm task and close the channel.
    fn post_stop(&mut self) {
        let _ = self.send_swarm_task(CommunicationRequest::Shutdown, None);
        if let Some(swarm_handle) = self.poll_swarm_handle.take() {
            task::block_on(swarm_handle);
        }
        if let Some(mut swarm_tx) = self.swarm_tx.take() {
            swarm_tx.disconnect()
        }
    }

    // Forward the received events to the task that is managing the swarm communication.
    fn recv(&mut self, ctx: &Context<Self::Msg>, msg: Self::Msg, sender: Sender) {
        let res = self.send_swarm_task(msg, sender);
        if let Err(err) = res {
            if err.is_disconnected() {
                ctx.stop(ctx.myself())
            }
        }
    }
}

impl<Req, Res, ClientMsg> CommunicationActor<Req, Res, ClientMsg>
where
    Req: MessageEvent + VariantPermission + Into<ClientMsg>,
    Res: MessageEvent,
    ClientMsg: Message,
{
    // Forward a request over the channel to the swarm task.
    fn send_swarm_task(&mut self, msg: CommunicationRequest<Req, ClientMsg>, sender: Sender) -> Result<(), SendError> {
        if let Some(mut tx) = self.swarm_tx.clone() {
            return task::block_on(future::poll_fn(move |tcx: &mut TaskContext<'_>| {
                match tx.poll_ready(tcx) {
                    Poll::Ready(Ok(())) => Poll::Ready(tx.start_send((msg.clone(), sender.clone()))),
                    Poll::Ready(err) => Poll::Ready(err),
                    Poll::Pending => Poll::Pending,
                }
            }));
        }
        Ok(())
    }
}
