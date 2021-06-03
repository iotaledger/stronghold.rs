// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub mod behaviour;
pub use behaviour::{firewall, types::*, NetBehaviourConfig};
pub mod libp2p {
    pub use libp2p::{identity::Keypair, Multiaddr, PeerId};
}

#[macro_export]
macro_rules! unwrap_or_return (
    ($expression:expr) => {
        match $expression {
            Some(e) => e,
            None => return
        }
    };
);
