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
// TODO: Add ability to read and revoke records not on the head of the chain.
// TODO: Add Reference types for the RecordIds and VaultIds to expose to the External programs.

use thiserror::Error as DeriveError;

mod actors;
mod bucket;
mod client;
mod ids;
mod key_store;
mod provider;
mod secret;
mod snapshot;

use crate::{
    bucket::Bucket,
    client::{Client, SHResults},
    key_store::KeyStore,
    provider::Provider,
    snapshot::Snapshot,
};

use riker::actors::{channel, ActorRefFactory, ActorSystem, ChannelRef};

pub use crate::ids::{ClientId, VaultId};

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

/// Creates the ActorSystem for stronghold and attaches the actors.  Returns the ActorSystem and the Channel.
pub fn init_stronghold() -> (ActorSystem, ChannelRef<SHResults>) {
    let sys = ActorSystem::new().unwrap();
    let chan: ChannelRef<SHResults> = channel("external", &sys).unwrap();

    sys.actor_of_args::<Client, _>("client", chan.clone()).unwrap();
    sys.actor_of::<Bucket<Provider>>("bucket").unwrap();
    sys.actor_of::<KeyStore<Provider>>("keystore").unwrap();
    sys.actor_of::<Snapshot>("snapshot").unwrap();

    (sys, chan)
}
