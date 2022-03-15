// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! # Stronghold-P2p
//!
//! This crate implements a secure P2P-communication layer for [`Stronghold`][<https://docs.rs/iota_stronghold/>],
//! which enables permissioned use of remote strongholds for creating services like remote signing.
//! However, while being significantly influenced by Stronghold's use-case, it is not dependent on the Stronghold crate
//! itself and may be used independently.
//!
//! Stronghold-P2p is using the libp2p networking framework.
//! On top of libp2p's protocols for describing how and what data is send through the network, the [`StrongholdP2p`]
//! interface provides an additional layer of abstraction and manages the network polling and all interaction in a
//! separate task. Futhermore, it integrates a firewall with which rules can be set to restrict requests and/ or ask for
//! dynamic approval before forwarding them.

pub mod behaviour;
mod libp2p_reexport {
    pub use libp2p::{core::Executor, identity, swarm::DialError, Multiaddr, PeerId};
    pub type AuthenticKeypair = libp2p::noise::AuthenticKeypair<libp2p::noise::X25519Spec>;
    pub type NoiseKeypair = libp2p::noise::Keypair<libp2p::noise::X25519Spec>;
}
mod interface;
mod serde;

pub use behaviour::{
    assemble_relayed_addr, firewall, AddressInfo, BehaviourState, EstablishedConnections, MessageProtocol,
    RelayNotSupported,
};
pub use interface::*;
pub use libp2p_reexport::*;

#[macro_export]
macro_rules! unwrap_or_return (
    ($expression:expr) => {
        match $expression {
            Some(e) => e,
            None => return
        }
    };
);
