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

use arguments::*;
use clap::Clap;

use futures::executor::block_on;
use iota_stronghold::{ResultMessage, Stronghold};

#[cfg(feature = "communication")]
use iota_stronghold::Multiaddr;

use riker::actors::*;
use std::error::Error;

/// Callback type for blocking stronghold instance
type Callback = fn() -> Result<(), Box<dyn Error>>;

/// create a line error with the file and the line number
#[macro_export]
macro_rules! line_error {
    () => {
        concat!("Error at ", file!(), ":", line!())
    };
    ($str:expr) => {
        concat!($str, " @", file!(), ":", line!())
    };
}

/// Returns a list of all available peers
#[cfg(feature = "communication")]
fn list_peers_command(stronghold: &mut iota_stronghold::Stronghold) -> Result<(), Box<dyn Error>> {
    match block_on(stronghold.get_swarm_info()) {
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
#[cfg(feature = "communication")]
fn show_swarm_info_command(stronghold: &mut iota_stronghold::Stronghold) -> Result<(), Box<dyn Error>> {
    stronghold.spawn_communication();

    match block_on(stronghold.get_swarm_info()) {
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

#[cfg(feature = "communication")]
fn start_listening_command(
    multiaddr: &str,
    stronghold: &mut iota_stronghold::Stronghold,
) -> Result<(), Box<dyn Error>> {
    let multiaddress: Multiaddr = multiaddr.parse()?;

    // spawn communication actor
    let comm = stronghold.spawn_communication();
    println!("Communication actor spawned: {:?}", comm);

    // start listening
    let result = block_on(stronghold.start_listening(Some(multiaddress)));
    println!("Listening on addr: {:?}", result);

    // blocks
    stronghold.keep_alive(None::<Callback>);

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let app = ExampleApp::parse();
    let system = ActorSystem::new().expect(line_error!());
    let client_path = app.actor_path.as_bytes().to_vec();
    let mut stronghold = Stronghold::init_stronghold_system(system, client_path, vec![]);

    match app.cmds {
        #[cfg(feature = "communication")]
        Commands::Relay { .. } => {
            todo!()
        }
        #[cfg(feature = "communication")]
        Commands::Peers {} => list_peers_command(&mut stronghold),

        #[cfg(feature = "communication")]
        Commands::SwarmInfo {} => show_swarm_info_command(&mut stronghold),

        #[cfg(feature = "communication")]
        Commands::Listen { multiaddr } => start_listening_command(multiaddr.as_str(), &mut stronghold),
    }
}
