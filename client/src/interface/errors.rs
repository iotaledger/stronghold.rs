// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "p2p")]
pub use p2p_errors::*;

use crate::state::snapshot;

use actix::MailboxError;
use std::fmt::Debug;
use thiserror::Error as DeriveError;

#[derive(DeriveError, Debug)]
pub enum ActorError {
    #[error("Error sending message to Actor: `{0}`")]
    Mailbox(#[from] MailboxError),
    #[error("Target Actor has not been spawned or was killed.")]
    TargetNotSpawned,
}

#[derive(DeriveError, Debug)]
pub enum WriteVaultError {
    #[error("Actor Error: `{0}`")]
    Actors(#[from] ActorError),
    #[error("Fatal Engine Error: `{0}`")]
    Engine(String),
}

#[derive(DeriveError, Debug)]
pub enum ReadSnapshotError {
    #[error("Actor Error: `{0}`")]
    Actors(#[from] ActorError),
    #[error("Read Snapshot Error: `{0}`")]
    Read(#[from] snapshot::ReadError),
}
#[derive(DeriveError, Debug)]
pub enum WriteSnapshotError {
    #[error("Actor Error: `{0}`")]
    Actors(#[from] ActorError),
    #[error("Write Snapshot Error: `{0}`")]
    Write(#[from] snapshot::WriteError),
}

impl From<MailboxError> for WriteVaultError {
    fn from(e: MailboxError) -> Self {
        WriteVaultError::Actors(e.into())
    }
}

impl From<MailboxError> for ReadSnapshotError {
    fn from(e: MailboxError) -> Self {
        ReadSnapshotError::Actors(e.into())
    }
}

impl From<MailboxError> for WriteSnapshotError {
    fn from(e: MailboxError) -> Self {
        WriteSnapshotError::Actors(e.into())
    }
}

#[cfg(feature = "p2p")]
mod p2p_errors {

    use super::*;
    use p2p::{DialErr, ListenErr, ListenRelayErr, OutboundFailure};
    use std::io;

    #[derive(DeriveError, Debug)]
    pub enum SpawnNetworkError {
        #[error("Actor Mailbox Error: `{0}`")]
        ActorMailbox(#[from] MailboxError),

        #[error("Error: Network already running.")]
        AlreadySpawned,

        #[error("Io Error: `{0}`")]
        Io(#[from] io::Error),
    }

    #[derive(DeriveError, Debug)]
    pub enum DialError {
        #[error("Local Actor Error: `{0}`")]
        LocalActors(#[from] ActorError),
        #[error("Dial Error: `{0}`")]
        Dial(#[from] DialErr),
    }

    #[derive(DeriveError, Debug)]
    pub enum ListenError {
        #[error("Local Actor Error: `{0}`")]
        LocalActors(#[from] ActorError),
        #[error("Listen Error: `{0}`")]
        Listen(#[from] ListenErr),
    }

    #[derive(DeriveError, Debug)]
    pub enum ListenRelayError {
        #[error("Local Actor Error: `{0}`")]
        LocalActors(#[from] ActorError),
        #[error("Listen Relay Error: `{0}`")]
        ListenRelay(#[from] ListenRelayErr),
    }

    #[derive(DeriveError, Debug)]
    pub enum P2PError {
        #[error("Local Actor Error: `{0}`")]
        LocalActors(#[from] ActorError),
        #[error("Outbound Failure: `{0}`")]
        OutboundFailure(#[from] OutboundFailure),
    }

    #[derive(DeriveError, Debug)]
    pub enum WriteRemoteVaultError {
        #[error("P2P Error: `{0}`")]
        P2P(#[from] P2PError),
        #[error("Remote Engine Error `{0}`")]
        RemoteEngine(String),
    }

    impl From<MailboxError> for P2PError {
        fn from(e: MailboxError) -> Self {
            P2PError::LocalActors(e.into())
        }
    }

    impl From<MailboxError> for DialError {
        fn from(e: MailboxError) -> Self {
            DialError::LocalActors(e.into())
        }
    }

    impl From<MailboxError> for ListenError {
        fn from(e: MailboxError) -> Self {
            ListenError::LocalActors(e.into())
        }
    }

    impl From<MailboxError> for ListenRelayError {
        fn from(e: MailboxError) -> Self {
            ListenRelayError::LocalActors(e.into())
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
