// Copyright 2020 IOTA Stiftung
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

mod msg_handler;
use msg_handler::Handler;

use communication::{behaviour::P2PNetworkBehaviour, P2P};
use clap::{load_yaml, App, ArgMatches};
use libp2p::core::{identity::Keypair, Multiaddr, PeerId};

// Put a record into the mailbox
fn put_record(matches: &ArgMatches) {
    if let Some(matches) = matches.subcommand_matches("put_mailbox") {
        if let Some(mail_id) = matches
            .value_of("mailbox_id")
            .and_then(|id_arg| PeerId::from_str(id_arg.as_str()).ok())
        {
            if let Some(mail_addr) = matches
                .value_of("mailbox_addr")
                .and_then(|addr_arg| Multiaddr::from_str(&*addr_arg).ok())
            {
                if let Some(key) = matches.value_of("key") {
                    if let Some(value) = matches.value_of("value") {
                        let local_keys = Keypair::generate_ed25519();
                        let local_peer_id = PeerId::from(local_keys.public());
                        let timeout = matches.value_of("timeout").map(|timeout| timeout.parse::<u64>());
                        let behaviour = P2PNetworkBehaviour::new(local_peer_id, timeout, Handler);
                        let communication = P2P::new(behaviour, local_keys, None, (mail_id, mail_addr));
                        let request_id = communication.put_record_mailbox(key, value, None, None);
                        if request_id.is_ok() {
                            println!("Successfully send record to mailbox");
                            return;
                        }
                    }
                }
            }
        }
    }
    eprintln!("Could not send record to mailbox");
}

fn main() {
    let yaml = load_yaml!("cli.yml");
    let matches = App::from(yaml).get_matches();
    put_record(&matches);
}
