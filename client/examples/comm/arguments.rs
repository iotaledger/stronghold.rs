// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/// CLI arguments module
use clap::{Clap, Subcommand};

#[derive(Clap, Debug)]
#[clap(
    name = "Stronghold Example Communications",
    about = "Example to show stronghold's communication capabilities"
)]
pub struct ExampleApp {
    #[clap(subcommand)]
    pub cmds: Commands,

    #[clap(default_value = "actor_path")]
    pub actor_path: String,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    #[cfg(feature = "communication")]
    #[clap(alias = "relay", about = "Relay traffic to a peer.")]
    Relay {
        #[clap(long, short = 'p', required = true)]
        path: String,

        #[clap(long, short = 'i', required = true)]
        id: String,
    },
    #[cfg(feature = "communication")]
    #[clap(alias = "peers", about = "Lists all peers.")]
    Peers {},

    #[cfg(feature = "communication")]
    #[clap(alias = "swarm-info", about = "Displays information on this node")]
    SwarmInfo {},

    #[cfg(feature = "communication")]
    #[clap(about = "Start listening on multiaddress.")]
    Listen {
        #[clap(
            long = "multiaddr",
            short = 'm',
            about = r#"The multiaddress to listen on. Format "(/<protoName string>/<value string>)+" "#
        )]
        multiaddr: String,
    },
}
