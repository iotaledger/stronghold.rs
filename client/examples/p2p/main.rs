// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/// # Stronghold P2P-Network Examples
///
/// The p2p-network examples show the networking capabilities of stronghold.
/// Some are just "one-shot" examples to show what is possible with stronghold in an easy way
///
/// ## Listen for connections
/// To start stronghold to listen for remote peer connections, you can run
/// ```no_run
/// cargo run --features p2p --example p2p listen --multiaddr "/ip4/127.0.0.1/tcp/7001"
/// ```
///
/// ## Show swarm info
///
/// To show info on neighbouring peers you can run
/// ```no_run
/// cargo run --features p2p --example p2p swarm-info
/// ```
///
/// ## Add Peer(s)
/// Peers can also be added by running
/// ```no_run
/// cargo run --features p2p --example p2p
/// ```
mod arguments;
use arguments::*;

pub use clap::Clap;
use iota_stronghold::p2p::{Multiaddr, NetworkConfig, SwarmInfo};
pub use iota_stronghold::{ResultMessage, Stronghold};
use p2p::firewall::Rule;
pub use std::error::Error;

/// Returns a list of all available peers
pub async fn list_peers_command(stronghold: &mut iota_stronghold::Stronghold) -> Result<(), Box<dyn Error>> {
    let SwarmInfo { connections, .. } = stronghold.get_swarm_info().await?;
    let peers = connections.into_iter().map(|(p, _)| p);
    let info = format!(
        r#"
    Peers
    ===
    {:?}
    "#,
        peers
    );
    println!("{}", info);

    Ok(())
}

/// Displays the swarm info of this stronghold instance
pub async fn show_swarm_info_command(stronghold: &mut iota_stronghold::Stronghold) -> Result<(), Box<dyn Error>> {
    stronghold.spawn_p2p(Rule::AllowAll, NetworkConfig::default()).await?;

    let SwarmInfo {
        local_peer_id,
        listeners,
        connections,
    } = stronghold.get_swarm_info().await?;
    let addrs = listeners.into_iter().map(|l| l.addrs).flatten();
    let peers = connections.into_iter().map(|(p, _)| p);
    let info = format!(
        "-----------\nSwarm Info:\n-----------\nPeer Id : {},\nAddresses: {:?},\nPeers: {:?}\n",
        local_peer_id, addrs, peers
    );

    println!("{}", info);
    Ok(())
}

pub async fn start_listening_command(
    multiaddr: &str,
    stronghold: &mut iota_stronghold::Stronghold,
) -> Result<(), Box<dyn Error>> {
    let multiaddress: Multiaddr = multiaddr.parse()?;

    // spawn network actor
    let network = stronghold.spawn_p2p(Rule::AllowAll, NetworkConfig::default()).await;
    println!("Network actor spawned: {:?}", network);

    // start listening
    let result = stronghold.start_listening(Some(multiaddress)).await;
    println!("Listening on addr: {:?}", result);

    Ok(())
}

#[actix::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = ExampleApp::parse();
    let client_path = app.actor_path.as_bytes().to_vec();

    let mut stronghold = Stronghold::init_stronghold_system(client_path, vec![]).await?;

    return match app.cmds {
        Commands::Peers {} => list_peers_command(&mut stronghold).await,
        Commands::SwarmInfo {} => show_swarm_info_command(&mut stronghold).await,
        Commands::Listen { multiaddr } => start_listening_command(multiaddr.as_str(), &mut stronghold).await,
    };
}
