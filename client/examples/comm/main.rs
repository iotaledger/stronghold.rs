// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/// # Strong Communications Examples
///
/// todo
///
/// ## Listen for connections
/// todo
///
/// ## Show swarm info
/// todo
///
/// ## Add Peer(s)
/// todo
///
/// ## Connect to peer to exchange secrets
/// todo
///
/// ## Setup relay node
/// todo
///
mod arguments;

use arguments::*;
use clap::Clap;
use crypto::keys::x25519::PublicKey;
use futures::{
    channel::mpsc::{channel, Receiver, Sender},
    executor::block_on,
    StreamExt,
};
use iota_stronghold::{home_dir, naive_kdf, Location, PeerId, RecordHint, ResultMessage, StatusMessage, Stronghold};

#[cfg(feature = "communication")]
use iota_stronghold::Multiaddr;

use riker::actors::*;
use std::error::Error;

use std::path::{Path, PathBuf};

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

// /// Relays a request to a remote stronghold instance.
// #[cfg(feature = "communication")]
// fn relay_command(stronghold: &mut iota_stronghold::Stronghold, client_path: Vec<u8>) -> Result<(), Box<dyn Error>> {

//     todo!()
// }

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
        ResultMessage::Error(e) => return Err(Box::from(format!("{}", e))),
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
                "
Swarm Info:
===
Peer Id : {},
Addresses: {:?},
Peers: {:?}
            ",
                peer_id, addresses, peers
            );

            println!("{}", info)
        }
        ResultMessage::Error(e) => return Err(Box::from(format!("{}", e))),
    }
    Ok(())
}

#[cfg(feature = "communication")]
fn start_listening_command(
    multiaddr: &str,
    stronghold: &mut iota_stronghold::Stronghold,
    client_path: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    let multiaddress: Multiaddr = multiaddr.parse()?;

    // spawn communication actor
    let comm = stronghold.spawn_communication();
    println!("Communication actor spawned: {:?}", comm);

    let result = block_on(stronghold.start_listening(Some(multiaddress)));
    println!("Listening on addr: {:?}", result);

    // some blocking code
    // we need to keep `_tx`, otherwise it will be dropped and the channel will
    // be closed, making the blocking operation obsolete
    let (_tx, rx): (Sender<usize>, Receiver<usize>) = channel(1);

    let waiter = async {
        rx.map(|f| f).collect::<Vec<usize>>().await;
    };

    block_on(waiter);

    // todo!()
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let app = ExampleApp::parse();
    let system = ActorSystem::new().expect(line_error!());
    let client_path = app.actor_path.as_bytes().to_vec();
    let mut stronghold = Stronghold::init_stronghold_system(system, client_path.clone(), vec![]);

    match app.cmds {
        #[cfg(feature = "communication")]
        Commands::Relay { id, path } => {
            todo!()
        }
        #[cfg(feature = "communication")]
        Commands::Peers {} => list_peers_command(&mut stronghold),

        #[cfg(feature = "communication")]
        Commands::SwarmInfo {} => show_swarm_info_command(&mut stronghold),

        #[cfg(feature = "communication")]
        Commands::Listen { multiaddr } => start_listening_command(multiaddr.as_str(), &mut stronghold, client_path),
    }
}
