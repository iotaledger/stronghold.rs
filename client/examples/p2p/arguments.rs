// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/// CLI arguments module
use clap::Parser;

#[derive(Parser, Debug)]
#[clap(
    name = "Stronghold Example P2p-Network",
    about = "Example to show stronghold's p2p-network capabilities"
)]
pub struct ExampleApp {
    #[clap(subcommand)]
    pub cmds: Commands,

    #[clap(default_value = "actor_path")]
    pub actor_path: String,
}

#[derive(Debug, Parser)]
pub enum Commands {
    #[cfg(feature = "p2p")]
    #[clap(alias = "peers", about = "Lists all peers.")]
    Peers {},

    #[cfg(feature = "p2p")]
    #[clap(alias = "swarm-info", about = "Displays information on this node")]
    SwarmInfo {},

    #[cfg(feature = "p2p")]
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
