// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod behaviour;
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
