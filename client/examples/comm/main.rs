// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/// # Strong Communications Examples
///
/// The communication examples show the networking capabilities of stronghold.
/// Some are just "one-shot" examples to show what is possible with stronghold in an easy way
///
/// ## Listen for connections
/// To start stronghold to listen for remote peer connections, you can run
/// ```no_run
/// cargo run --features communication --example comm listen --multiaddr "/ip4/127.0.0.1/tcp/7001"
/// ```
///
/// ## Show swarm info
///
/// To show info on neighbouring peers you can run
/// ```no_run
/// cargo run --features communication --example comm swarm-info
/// ```
///
/// ## Add Peer(s)
/// Peers can also be added by running
/// ```no_run
/// cargo run --features communication --example comm
/// ```
mod arguments;

#[cfg(feature = "communication")]
use inner::*;

#[cfg(feature = "communication")]
mod inner {

    pub use super::arguments::*;
    pub use clap::Clap;
    pub use iota_stronghold::{Multiaddr, ResultMessage, Stronghold};
    pub use std::error::Error;

    /// Returns a list of all available peers

    pub async fn list_peers_command(stronghold: &mut iota_stronghold::Stronghold) -> Result<(), Box<dyn Error>> {
        match stronghold.get_swarm_info().await {
            ResultMessage::Ok((_, _, peers)) => {
                let info = format!(
                    r#"
            Peers
            ===
            {:?}
            "#,
                    peers
                );
                println!("{}", info)
            }
            ResultMessage::Error(e) => return Err(Box::from(format!("{:?}", e))),
        }

        Ok(())
    }

    /// Displays the swarm info of this stronghold instance
    pub async fn show_swarm_info_command(stronghold: &mut iota_stronghold::Stronghold) -> Result<(), Box<dyn Error>> {
        stronghold.spawn_communication();

        match stronghold.get_swarm_info().await {
            ResultMessage::Ok((peer_id, addresses, peers)) => {
                let info = format!(
                    "-----------\nSwarm Info:\n-----------\nPeer Id : {},\nAddresses: {:?},\nPeers: {:?}\n",
                    peer_id, addresses, peers
                );

                println!("{}", info)
            }
            ResultMessage::Error(e) => return Err(Box::from(format!("{:?}", e))),
        }

        Ok(())
    }

    pub async fn start_listening_command(
        multiaddr: &str,
        stronghold: &mut iota_stronghold::Stronghold,
    ) -> Result<(), Box<dyn Error>> {
        let multiaddress: Multiaddr = multiaddr.parse()?;

        // spawn communication actor
        let comm = stronghold.spawn_communication();
        println!("Communication actor spawned: {:?}", comm);

        // start listening
        let result = stronghold.start_listening(Some(multiaddress)).await;
        println!("Listening on addr: {:?}", result);

        Ok(())
    }
}
#[actix::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "communication")]
    {
        let app = ExampleApp::parse();
        let client_path = app.actor_path.as_bytes().to_vec();

        let mut stronghold = Stronghold::init_stronghold_system(client_path, vec![]).await?;

        return match app.cmds {
            Commands::Peers {} => list_peers_command(&mut stronghold).await,
            Commands::SwarmInfo {} => show_swarm_info_command(&mut stronghold).await,
            Commands::Listen { multiaddr } => start_listening_command(multiaddr.as_str(), &mut stronghold).await,
        };
    }

    #[cfg(not(feature = "communication"))]
    Ok(())
}
