// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod behaviour;
mod libp2p_reexport {
    pub use libp2p::{
        core::{connection::ConnectionLimits, Executor},
        identity::Keypair,
        noise::{AuthenticKeypair, Keypair as NoiseKeypair},
        swarm::DialError,
        Multiaddr, PeerId,
    };
}
pub use libp2p_reexport::*;
mod interface;
pub use behaviour::{assemble_relayed_addr, firewall, EstablishedConnections, MessageProtocol, RelayNotSupported};
pub use interface::*;

#[macro_export]
macro_rules! unwrap_or_return (
    ($expression:expr) => {
        match $expression {
            Some(e) => e,
            None => return
        }
    };
);
