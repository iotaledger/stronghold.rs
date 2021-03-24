// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! # Stronghold Communication
//!
//! This crate enables strongholds on different devices and in different networks to communicate with each other.
//! The main basis for its functionality is the [`libp2p`] crate, which is a system of protocols, specifications
//! and libraries that enable the development of peer-to-peer network applications
//!
//! The library provides two options to use communication, either directly with the [`P2PNetworkBehaviour`],
//! or by using the [`CommunicationActor`] within a [`ActorSystem`].
//!
//! ## P2PNetworkBehaviour
//!
//! The P2pNetworkBehaviour implements the [`NetworkBehaviour`] by combining multiple protocols of Libp2p:
//! - Multiplexing following the [Yamux specification](https://!github.com/hashicorp/yamux/blob/master/spec.md)
//! - Noise: Encryption of the communication using the [Noise protocol](https://!noiseprotocol.org/noise.html) with
//!   XX-Handshake
//! - Multicast DNS: Enable Peer Discovery in a local network
//! - Identify Protocol: Receive identifying information like the `PeerId` and listening addresses when connecting to a
//!   new peer.
//! - Request-Response Protocol: Allows sending direct request/response messages between Peers; it expects a response
//!   for each request
//!  
//! Upon creating a new instance, a transport is created and upgraded, and combined with the P2PNetworkBehaviour into
//! a [`ExpandedSwarm`].
//! This Swarm is returned to the caller and serves as entry-point for all communication to other peers.
//! Additional to the Libp2p methods of the [`ExpandedSwarm`], it enables sending outbound messages, and manages the
//! known peers. Incoming [`P2PEvents`] can be handled by polling from the swarm, e.g. via the [`next`] method.
//!
//! ### Example
//! ```no_run
//! use async_std::task;
//! use communication::behaviour::{BehaviourConfig, P2PNetworkBehaviour};
//! use libp2p::identity::Keypair;
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Debug, Clone, Serialize, Deserialize)]
//! pub enum Request {
//!     Ping,
//! }
//!
//! #[derive(Debug, Clone, Serialize, Deserialize)]
//! pub enum Response {
//!     Pong,
//! }
//!
//! let local_keys = Keypair::generate_ed25519();
//! let config = BehaviourConfig::default();
//! let mut swarm = task::block_on(P2PNetworkBehaviour::<Request, Response>::init_swarm(local_keys, config))
//!     .expect("Init swarm failed.");
//! ```
//!
//! ## CommunicationActor
//!
//! The [`CommunicationActor`] is using the [`riker`] crate to implement the actor pattern.  
//! When creating a new [`CommunicationActor`], the actor creates a [`P2PNetworkBehaviour`] and continuously polls for
//! events, incoming requests are sent to the client actor that has to be provided in the [`CommunicationConfig`].
//!
//! All swarm interaction, and configuration of the [`CommunicationActor`] is accomplished by sending the appropriate
//! [`CommunicationRequest`] to it, for each [`CommunicationRequest`] a [`CommunicationResults`] is returned to the
//! sender, this also allows using the [ask pattern](https://!riker.rs/patterns/#ask).
//!
//! ### Firewall
//! The communication actor implements a firewall that checks the permission of each outgoing and incoming requests and
//! drops them if the necessary permission has not been set. The required [`ToPermissionVariants`] trait for messages
//! can be derived with the [`communication-macros`], this allows in case of enum Request
//! types to accept specific variants while rejecting others.

pub mod actor;
pub mod behaviour;
pub mod libp2p {
    //! Re-export [`libp2p`] types.
    pub use libp2p::{
        core::{
            connection::ConnectionLimit, identity::Keypair, multiaddr::Protocol, ConnectedPoint, Multiaddr, PeerId,
        },
        swarm::{Swarm, SwarmEvent},
    };
}
