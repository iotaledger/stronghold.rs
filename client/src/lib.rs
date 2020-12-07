// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// TODO: Synchronization via 4th actor and status type.
// TODO: Add supervisors
// TODO: Add documentation
// TODO: Encrypted Return Channel
// TODO: Handshake
// TODO: O(1) comparison for IDS.
// TODO: Remove #[allow(dead_code)]s.
// TODO: ~~Add ability to name snapshots~~
// TODO: ~~Add ability to read and revoke records not on the head of the chain.~~
// TODO: Add Reference types for the RecordIds and VaultIds to expose to the External programs.
// TODO: Add Handshake Messages.
// TODO: Add Responses for each Message.

use thiserror::Error as DeriveError;

mod actors;
mod ask;
mod bucket;
mod client;
mod ids;
mod key_store;
mod provider;
mod runtime;
mod secret;
mod snapshot;

#[allow(non_snake_case, dead_code)]
mod hd;

use crate::{client::Client, runtime::Runtime, snapshot::Snapshot};

use riker::actors::{channel, ActorRefFactory, ActorSystem, ChannelRef};

pub use crate::{
    ask::ask,
    ids::{ClientId, VaultId},
    provider::Provider,
};

pub use engine::vault::{RecordHint, RecordId};

#[macro_export]
macro_rules! line_error {
    () => {
        concat!("Error at ", file!(), ":", line!())
    };
    ($str:expr) => {
        concat!($str, " @", file!(), ":", line!())
    };
}

pub type Result<T> = anyhow::Result<T, Error>;

#[derive(DeriveError, Debug)]
pub enum Error {
    #[error("Id Error")]
    IDError,
    #[error("Vault Error: {0}")]
    VaultError(#[from] engine::vault::Error),
}


// pub fn init_stronghold(sys: ActorSystem, data: Vec<u8>, path: Vec<u8>) -> (ActorSystem, ChannelRef<SHResults>) {
//     let chan: ChannelRef<SHResults> = channel("external", &sys).unwrap();

//     sys.actor_of::<InternalActor<Provider>>("internal-actor").unwrap();
//     sys.actor_of::<Snapshot>("snapshot").unwrap();
//     sys.actor_of::<Runtime>("runtime").unwrap();
//     sys.actor_of_args::<Client, _>("stronghold-internal", (chan.clone(), data, path))
//         .unwrap();

//     (sys, chan)
// }
