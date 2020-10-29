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

//! ## Introduction
//!
//! This library enables strongholds on different devices and in different networks to communicate with each other.
//! The main basis for its functionality is the rust-libp2p library, which is a system of protocols, specifications, and
//! libraries that enable the development of peer-to-peer network applications (https://libp2p.io/).
//!
//! Libp2p was originally the network protocol of IPFS and has evolved into a modular system with implementations in
//! Node.js, Go and Rust. It is important to note that at the current status, the Rust implementation doesn't have all
//! features yet and especially peer discovery in different networks, NAT Traversal and Firewalls pose a problem, that
//! we solved for stronghold by using a mailbox concept that is described later.
//!
//! ## Transport and the Swarm
//!
//! Libp2p uses the term `transport` for their lowest layer that is responsible for sending and receiving data over a
//! network. The current rust implementation supports tcp and websockets, and apart from that provides the option to
//! upgrade a connection with protocols for multiplexing and authentication.
//! This stronghold-communication library uses yamux for multiplexing and the noise-protocol for authentication.
//!
//! The second important concept of libp2p is its `Swarm` (in newer implementations and documents also called `Switch`).
//! The swarm is responsible for negotiating protocols, managing transports and sending and receiving messages via
//! different protocols. It is possible to combine different protocols into a so called `NetworkBehaviour`, which is
//! what this library is doing. Stronghold-communication uses multicast DNS (mDNS) for peer discovery in a local
//! network, libp2p-kademlia as a distributed hash table for managing known peers in kbuckets and publishing / reading
//! records, and the RequestResponse protocol in order to send / receive custom messages and parse them.
//!
//! ## Stronghold-Communication
//!
//! Similar to the swarm in libp2p, the stronghold-communication creates the `P2PNetworkBehaviour` struct that manages
//! sending messages, querying kademlia and reacting upon the outcome of these operation. In order to enable a custom
//! behaviour on events, a `InboundEventCodec` has to be implemented for the `P2PNetworkBehaviour` when creating a new
//! instance. This `InboundEventCodec` has to implement the methods `handle_request_msg`, `handle_response_msg` and
//! `handle_kademlia_event` and can use methods of the `SwarmContext` that is already implemented for
//! `P2PNetworkBehaviour` and which provides a range of outbound operations.
//!
//! The main entry point for all communication with other peers is the `P2PNetwork`.
//! It creates the transport and the swarm for the prior created `P2PNetworkBehaviour` and listens for incoming
//! connections. It has multiple listening addresses due to libp2ps concept of `multiaddresses` that encode different
//! addressing schemes for different protocols. Apart from IPv4 and IPv6 Addresses, these multiaddresses can also be dns
//! addresses, which is relevant if a peer is listening to such an address on a server. The listed multiaddresses are
//! only the ones within the same local network, but if port forwarding was configured, the local /ip4/my-local-address/
//! tcp/12345 Address can be replaced by the public one or by `/dns/my.public.server.address/tcp/12345`, where the
//! `/tcp/12345` part describes the port.
//!
//!
//! It provides methods for dialing and connection other peers, using the swarm behaviour via its `swarm` property (that
//! enables using methods from the `P2PNetworkBehaviour`) and managing mailboxes if necessary.
//!
//! ## Mailbox Concept
//!
//! Since not all peers can be dialed directly e.g. because they are behind a firewall, stronghold-communication
//! includes methods for using a mailbox. The mailbox is a peer running on a server with public IP Address that can be
//! reached by all other peers. If can be used to deposit records for unavailable remote peers by sending a
//! `Request::Publish` message with the record to the mailbox, and e.g. implementing a behaviour for the mailbox where
//! it publishes the record in kademlia upon receiving such a message. The remote peer can then connect to the same
//! mailbox and query kademlia for the record. An example for this implementation is provided in /examples/mailbox.rs.

pub mod behaviour;
pub mod error;
pub mod message;
