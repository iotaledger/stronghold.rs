// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Stronghold Communication Feature Connection Example
//!
//! This example tries to connect to a remote stronghold instance
//!
//! run with
//! ```no_run
//! cargo run --example connect --features communication -- --relay-id <base58 addr string> --relay-address "/ip4/0.0.0.0/tcp/7001"
//! ```

use clap::Clap;
use futures::executor::block_on;
use iota::{Multiaddr, RelayDirection, ResultMessage};
use iota_stronghold as iota;
use log::*;
use std::{collections::HashMap, error::Error, str::FromStr};

#[cfg(feature = "communication")]
use iota::{ActorSystem, PeerId, Stronghold};

#[derive(Clap)]
#[clap(name = "Client Connect", about = "Remote Stronghold connection example")]
struct ConnectApp {
    #[clap(
        long,
        short = 'l',
        about = "Comma separated peer_id=multiaddr",
        value_delimiter = ","
    )]
    peers: Option<String>,

    #[clap(long, short = 'p', about = "The peer id of a relay server")]
    relay_id: PeerId,

    #[clap(long, short = 'r', about = "The multiaddress of the relay server")]
    relay_address: Multiaddr,
}

fn parse(input: String) -> Result<HashMap<PeerId, Multiaddr>, Box<dyn Error>> {
    let mut result: HashMap<PeerId, Multiaddr> = HashMap::new();

    for token in input.split(',') {
        let entry = parse_entry(token.to_string())?;
        result.insert(entry.0, entry.1);
    }

    Ok(result)
}

/// Tries to parse an entry consisting of a pair of "peer_id=multiaddr" as string
/// Returns a tuple of [`PeerId`] and [`Multiaddr`]
fn parse_entry(input: String) -> Result<(PeerId, Multiaddr), Box<dyn Error>> {
    let tokens: Vec<&str> = input.split('=').collect();

    let parsed_peer_id = PeerId::from_str(tokens[0])?;
    let parsed_multiaddr = Multiaddr::from_str(tokens[1])?;

    Ok((parsed_peer_id, parsed_multiaddr))
}

/// Tries to connect to (optional) peers and adds a relay
/// server in between.
fn connect_to(
    stronghold: &mut Stronghold,
    relay_id: PeerId,
    relay_address: Multiaddr,
    peers: Option<HashMap<PeerId, Multiaddr>>,
) -> Result<(), Box<dyn Error>> {
    stronghold.spawn_communication();

    block_on(async {
        stronghold.get_swarm_info().await;

        if let ResultMessage::Error(err) = stronghold
            .add_peer(relay_id, Some(relay_address), Some(RelayDirection::Both))
            .await
        {
            error!("Could not connect to relay. Cause :{}", err);
        }
    });

    if let Some(peers) = peers {
        info!("Adding peers");

        peers.into_iter().for_each(|(id, addr)| {
            block_on(async {
                stronghold.add_peer(id, Some(addr), None).await;
            });
        });
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    #[cfg(feature = "communication")]
    {
        let app = ConnectApp::parse();

        let client_path = b"client_path";
        let system = ActorSystem::new()?;
        let mut stronghold = Stronghold::init_stronghold_system(system, client_path.to_vec(), vec![]);

        let relay_id = app.relay_id;
        let relay_address = app.relay_address;

        let peers = match app.peers {
            Some(p) => Some(parse(p)?),
            None => None,
        };

        connect_to(&mut stronghold, relay_id, relay_address, peers)
    }

    #[cfg(not(feature = "communication"))]
    Err(Box::from(r#"Need to activate the "communication" feature"#))
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_parse() {
        let test_string =
            "12D3KooWGAS2jVkydjJp4DPcjAKKteC1gMBkTaxdH8vrrpFZecLR=/ip4/0.0.0.0/tcp/9001,12D3KooWQkhxr6iaYuoRpiQ4b6fDKHC3YMerKpA4Rnmk7TND9b6B=/ip4/0.0.0.0/tcp/9001".to_string();

        let result = parse(test_string);
        assert!(result.is_ok(), "Parsing config pairs failed {:?}", result);

        let map = result.unwrap();
        assert!(map.contains_key(&PeerId::from_str("12D3KooWQkhxr6iaYuoRpiQ4b6fDKHC3YMerKpA4Rnmk7TND9b6B").unwrap()));
    }
}
