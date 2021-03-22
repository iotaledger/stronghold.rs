// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! # Actor
//!
//! This module provides a riker actor that handles the communication to a remote peer over the swarm.
//!
//! The [`CommunicationActor `] sends the [`CommunicationRequest::RequestMsg`]s it receives over the swarm to the
//! corresponding remote peer and forwards incoming request to the client provided in the [`CommunicationConfig`].
//! Before forwarding any requests, the request will be validated by the firewall according to the configuration from
//! [`CommunicationConfig`], additional rules or changed can be set with [`CommunicationRequest::ConfigureFirewall`].
//! This requires that the [`ToPermissionVariants`] trait is implemented for the generic `Req` type, which can be
//! derived with the macro [`RequestPermissions`] from [`communication_macros`].
//!
//! If remote peers should be able to dial the local system, a [`CommunicationRequest::StartListening`] has to be sent
//! to the [`CommunicationActor`].
//!
//! ```no_run
//! use communication::{
//!     actor::{
//!         CommunicationActor, CommunicationActorConfig, FirewallPermission, PermissionValue, ToPermissionVariants,
//!         VariantPermission,
//!     },
//!     behaviour::BehaviourConfig,
//! };
//! use communication_macros::RequestPermissions;
//! use libp2p::identity::Keypair;
//! use riker::actors::*;
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Debug, Clone, Serialize, Deserialize, RequestPermissions)]
//! pub enum Request {
//!     Ping,
//! }
//!
//! #[derive(Debug, Clone, Serialize, Deserialize, RequestPermissions)]
//! pub enum Response {
//!     Pong,
//! }
//!
//! // blank client actor without any logic
//! #[derive(Clone, Debug)]
//! struct ClientActor;
//!
//! impl ActorFactory for ClientActor {
//!     fn create() -> Self {
//!         ClientActor
//!     }
//! }
//!
//! impl Actor for ClientActor {
//!     type Msg = Request;
//!
//!     fn recv(&mut self, _ctx: &Context<Self::Msg>, _msg: Self::Msg, sender: Sender) {
//!         sender
//!             .expect("Sender exists")
//!             .try_tell(Response::Pong, None)
//!             .expect("Sender received response");
//!     }
//! }
//!
//! let local_keys = Keypair::generate_ed25519();
//! let sys = ActorSystem::new().expect("Init actor system failed.");
//! let keys = Keypair::generate_ed25519();
//! let client = sys
//!     .actor_of::<ClientActor>("client")
//!     .expect("Init client actor failed.");
//! let actor_config = CommunicationActorConfig {
//!     client,
//!     firewall_default_in: FirewallPermission::all(),
//!     firewall_default_out: FirewallPermission::none(),
//! };
//! let behaviour_config = BehaviourConfig::default();
//! let comms_actor = sys
//!     .actor_of_args::<CommunicationActor<Request, Response, _, _>, _>(
//!         "communication",
//!         (local_keys, actor_config, behaviour_config),
//!     )
//!     .expect("Init communication actor failed.");
//! ```

mod connections;
mod firewall;
mod swarm_task;
mod types;
use crate::behaviour::{BehaviourConfig, MessageEvent};
use async_std::task;
use core::{
    marker::PhantomData,
    task::{Context as TaskContext, Poll},
};
use firewall::*;
pub use firewall::{
    FirewallPermission, FirewallRule, PermissionValue, RequestDirection, RequestPermissions, ToPermissionVariants,
    VariantPermission,
};
use futures::{
    channel::mpsc::{unbounded, SendError, UnboundedSender},
    future,
};
use libp2p::identity::Keypair;
use riker::actors::*;
use stronghold_utils::ask;
use swarm_task::SwarmTask;
pub use types::*;

#[derive(Debug, Clone)]
/// The actor configuration
pub struct CommunicationActorConfig<ClientMsg>
where
    ClientMsg: Message,
{
    /// Target client for incoming request
    pub client: ActorRef<ClientMsg>,
    /// Default restriction for incoming requests.
    pub firewall_default_in: FirewallPermission,
    /// Default restriction for outgoing requests.
    pub firewall_default_out: FirewallPermission,
}

/// Actor responsible for creating a [`P2PNetworkBehaviour`] and handling all interaction with the Swarm.
/// For each received [`CommunicationRequest`], a [`CommunicationResults`] is returned to the sender.
pub struct CommunicationActor<Req, Res, ClientMsg, P>
where
    Req: MessageEvent + ToPermissionVariants<P> + Into<ClientMsg>,
    Res: MessageEvent,
    ClientMsg: Message,
    P: Message + VariantPermission,
{
    // Channel for messages to the swarm task.
    swarm_tx: Option<UnboundedSender<(CommunicationRequest<Req, ClientMsg>, Sender)>>,
    swarm_task_config: Option<(Keypair, CommunicationActorConfig<ClientMsg>, BehaviourConfig)>,
    // Handle of the running swarm task.
    poll_swarm_handle: Option<future::RemoteHandle<()>>,
    _marker: (PhantomData<Res>, PhantomData<P>),
}

impl<Req, Res, ClientMsg, P> ActorFactoryArgs<(Keypair, CommunicationActorConfig<ClientMsg>, BehaviourConfig)>
    for CommunicationActor<Req, Res, ClientMsg, P>
where
    Req: MessageEvent + ToPermissionVariants<P> + Into<ClientMsg>,
    Res: MessageEvent,
    ClientMsg: Message,
    P: Message + VariantPermission,
{
    // Create a CommunicationActor that spawns a task to poll from the swarm.
    // The provided keypair is used to authenticate the swarm communication.
    // The client actor ref is used to forward incoming requests from the swarm to it.
    fn create_args(config: (Keypair, CommunicationActorConfig<ClientMsg>, BehaviourConfig)) -> Self {
        Self {
            swarm_tx: None,
            swarm_task_config: Some(config),
            poll_swarm_handle: None,
            _marker: (PhantomData, PhantomData),
        }
    }
}

impl<Req, Res, ClientMsg, P> Actor for CommunicationActor<Req, Res, ClientMsg, P>
where
    Req: MessageEvent + ToPermissionVariants<P> + Into<ClientMsg>,
    Res: MessageEvent,
    ClientMsg: Message,
    P: Message + VariantPermission,
{
    type Msg = CommunicationRequest<Req, ClientMsg>;

    // Spawn a task for polling the swarm and forwarding messages from/to remote peers.
    // A channel is created to send the messages that the [`CommunicationActor`] receives to that task.
    fn post_start(&mut self, ctx: &Context<Self::Msg>) {
        // Init task
        if let Some((keypair, actor_config, behaviour_config)) = self.swarm_task_config.take() {
            let (swarm_tx, swarm_rx) = unbounded();
            self.swarm_tx = Some(swarm_tx);

            let actor_system = ctx.system.clone();
            let swarm_task = task::block_on(SwarmTask::<_, Res, _, _>::new(
                actor_system,
                swarm_rx,
                actor_config,
                keypair,
                behaviour_config,
            ));
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

impl<Req, Res, ClientMsg, P> CommunicationActor<Req, Res, ClientMsg, P>
where
    Req: MessageEvent + ToPermissionVariants<P> + Into<ClientMsg>,
    Res: MessageEvent,
    ClientMsg: Message,
    P: Message + VariantPermission,
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
