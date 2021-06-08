// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub mod behaviour;
mod libp2p_reexport {
    pub use libp2p::{identity::Keypair, Multiaddr, PeerId};
}
pub use libp2p_reexport::*;
mod interface;
pub use behaviour::{
    firewall,
    types::{
        ConnectionErr, InboundFailure, NetworkEvents, OutboundFailure, ReceiveRequest, RequestDirection, RequestId,
        RequestMessage, ResponseReceiver, RqRsMessage,
    },
    CommunicationProtocol, NetBehaviourConfig,
};
pub use interface::{Listener, ShCommunication};

#[macro_export]
macro_rules! unwrap_or_return (
    ($expression:expr) => {
        match $expression {
            Some(e) => e,
            None => return
        }
    };
);
