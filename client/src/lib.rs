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
// TODO: Add Handshake Messages.

use thiserror::Error as DeriveError;

mod actors;
mod bucket;
mod client;
mod ids;
mod hd;
mod key_store;
mod provider;
mod secret;
mod snapshot;

use crate::{bucket::Bucket, client::Client, key_store::KeyStore, snapshot::Snapshot};

use riker::actors::{channel, ActorRefFactory, ActorSystem, ChannelRef};

pub use crate::{
    client::{ClientMsg, SHRequest, SHResults},
    ids::{ClientId, VaultId},
    provider::Provider,
};

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

/// Attaches the Stronghold Actors to the Riker `ActorSystem`.  Returns the ActorSystem and the a
/// `ChannelRef<SHResults>`.
pub fn init_stronghold(sys: ActorSystem) -> (ActorSystem, ChannelRef<SHResults>) {
    let chan: ChannelRef<SHResults> = channel("external", &sys).unwrap();

    sys.actor_of::<Bucket<Provider>>("bucket").unwrap();
    sys.actor_of::<KeyStore<Provider>>("keystore").unwrap();
    sys.actor_of::<Snapshot>("snapshot").unwrap();
    sys.actor_of_args::<Client, _>("stronghold-internal", chan.clone())
        .unwrap();

    (sys, chan)
}
