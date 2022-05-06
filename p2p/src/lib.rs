// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! # Stronghold-P2p
//!
//! This crate implements a secure P2P-communication layer for [`Stronghold`](<https://docs.rs/iota_stronghold/>).
//! It enables permissioned use of remote strongholds for creating services like remote signing.
//! However, while being significantly influenced by Stronghold's use-case, it is not dependent on the Stronghold crate
//! itself and may be used independently.
//!
//! Stronghold-P2p is using the [`libp2p`][libp2p] networking framework.
//! On top of libp2p's protocols for describing how and what data is send through the network, the [`StrongholdP2p`]
//! interface provides an additional layer of abstraction and manages the network polling and all interaction in a
//! event loop that runs in a separate task. Futhermore, it integrates a firewall with which rules can be set to
//! restrict requests and/ or ask for dynamic approval before forwarding them.

mod behaviour;
mod libp2p_reexport {
    pub use libp2p::{
        core::{ConnectedPoint, Executor},
        identity,
        swarm::DialError,
        Multiaddr, PeerId,
    };
    pub type AuthenticKeypair = libp2p::noise::AuthenticKeypair<libp2p::noise::X25519Spec>;
    pub type NoiseKeypair = libp2p::noise::Keypair<libp2p::noise::X25519Spec>;
}
mod interface;

pub use behaviour::{
    assemble_relayed_addr, firewall, AddressInfo, InboundFailure, OutboundFailure, PeerAddress, RelayNotSupported,
    Request, RequestId,
};
pub use interface::{
    ChannelSinkConfig, ConnectionErr, ConnectionLimits, DialErr, EventChannel, InitKeypair, ListenErr, ListenRelayErr,
    Listener, NetworkEvent, ReceiveRequest, StrongholdP2p, StrongholdP2pBuilder, TransportErr,
};
pub use libp2p_reexport::*;

#[macro_export(local_inner_macros)]
macro_rules! unwrap_or_return (
    ($expression:expr) => {
        match $expression {
            Some(e) => e,
            None => return
        }
    };
);
