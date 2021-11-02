// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "p2p")]
pub use p2p_errors::*;

use crate::state::snapshot;

use actix::MailboxError;
use std::fmt::Debug;
use thiserror::Error as DeriveError;

type Result<T, E> = std::result::Result<std::result::Result<T, E>, ActorError>;

#[derive(DeriveError, Debug)]
pub enum ActorError {
    #[error("actor mailbox error: `{0}`")]
    Mailbox(#[from] MailboxError),
    #[error("target actor has not been spawned or was killed")]
    TargetNotFound,
}

#[derive(DeriveError, Debug)]
pub enum WriteVaultError {
    #[error("actor error: `{0}`")]
    Actor(#[from] ActorError),
    #[error("fatal engine error: `{0}`")]
    Engine(String),
}

#[derive(DeriveError, Debug)]
pub enum ReadSnapshotError {
    #[error("actor error: `{0}`")]
    Actor(#[from] ActorError),
    #[error("read snapshot error: `{0}`")]
    Read(#[from] snapshot::ReadError),
}
#[derive(DeriveError, Debug)]
pub enum WriteSnapshotError {
    #[error("actor error: `{0}`")]
    Actor(#[from] ActorError),
    #[error("write snapshot error: `{0}`")]
    Write(#[from] snapshot::WriteError),
}

impl From<MailboxError> for WriteVaultError {
    fn from(e: MailboxError) -> Self {
        WriteVaultError::Actor(e.into())
    }
}

impl From<MailboxError> for ReadSnapshotError {
    fn from(e: MailboxError) -> Self {
        ReadSnapshotError::Actor(e.into())
    }
}

impl From<MailboxError> for WriteSnapshotError {
    fn from(e: MailboxError) -> Self {
        WriteSnapshotError::Actor(e.into())
    }
}

#[cfg(feature = "p2p")]
mod p2p_errors {

    use super::*;
    use p2p::{DialErr, ListenErr, ListenRelayErr, OutboundFailure, RelayNotSupported};
    use std::io;

    #[derive(DeriveError, Debug)]
    pub enum SpawnNetworkError {
        #[error("actor mailbox error: `{0}`")]
        ActorMailbox(#[from] MailboxError),

        #[error("network already running")]
        AlreadySpawned,

        #[error("I/O error: `{0}`")]
        Io(#[from] io::Error),
    }

    #[derive(DeriveError, Debug)]
    pub enum DialError {
        #[error("local actor error: `{0}`")]
        LocalActor(#[from] ActorError),
        #[error("dial error: `{0}`")]
        Dial(#[from] DialErr),
    }

    #[derive(DeriveError, Debug)]
    pub enum ListenError {
        #[error("local actor error: `{0}`")]
        LocalActor(#[from] ActorError),
        #[error("listen error: `{0}`")]
        Listen(#[from] ListenErr),
    }

    #[derive(DeriveError, Debug)]
    pub enum RelayError {
        #[error("local actor error: `{0}`")]
        LocalActor(#[from] ActorError),
        #[error("relay error: `{0}`")]
        Relay(#[from] ListenRelayErr),
    }

    #[derive(DeriveError, Debug)]
    pub enum P2PError {
        #[error("local actor error: `{0}`")]
        LocalActor(#[from] ActorError),
        #[error("outbound failure: `{0}`")]
        OutboundFailure(#[from] OutboundFailure),
    }

    #[derive(DeriveError, Debug)]
    pub enum WriteRemoteVaultError {
        #[error("p2p error: `{0}`")]
        P2P(#[from] P2PError),
        #[error("remote engine error `{0}`")]
        RemoteEngine(String),
    }

    impl From<MailboxError> for P2PError {
        fn from(e: MailboxError) -> Self {
            P2PError::LocalActor(e.into())
        }
    }

    impl From<MailboxError> for DialError {
        fn from(e: MailboxError) -> Self {
            DialError::LocalActor(e.into())
        }
    }

    impl From<MailboxError> for ListenError {
        fn from(e: MailboxError) -> Self {
            ListenError::LocalActor(e.into())
        }
    }

    impl From<MailboxError> for RelayError {
        fn from(e: MailboxError) -> Self {
            RelayError::LocalActor(e.into())
        }
    }

    impl From<RelayNotSupported> for RelayError {
        fn from(_: RelayNotSupported) -> Self {
            RelayError::Relay(ListenRelayErr::ProtocolNotSupported)
        }
    }

    impl From<MailboxError> for WriteRemoteVaultError {
        fn from(e: MailboxError) -> Self {
            WriteRemoteVaultError::P2P(e.into())
        }
    }

    impl From<ActorError> for WriteRemoteVaultError {
        fn from(e: ActorError) -> Self {
            WriteRemoteVaultError::P2P(e.into())
        }
    }

    impl From<OutboundFailure> for WriteRemoteVaultError {
        fn from(e: OutboundFailure) -> Self {
            WriteRemoteVaultError::P2P(e.into())
        }
    }
}
