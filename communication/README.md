## Introduction

This library enables strongholds on different devices and in different networks to communicate with each other.
The main basis for its functionality is the [rust-libp2p](https://github.com/libp2p/rust-libp2p) library, which is a system of protocols, specifications and 
libraries that enable the development of peer-to-peer network applications (https://libp2p.io/).

Libp2p was originally the network protocol of IPFS and has evolved into a modular system with implementations in 
Node.js, Go and Rust. It is important to note that at the current status, the Rust implementation doesn't have all features
yet and especially peer discovery in different networks, NAT Traversal and Firewalls pose a problem that we solved
for stronghold by using a mailbox concept that is described later.

## Transport and the Swarm

Libp2p uses the `transport` as the lowest layer, that is responsible for sending and receiving data over a network.
The current rust implementation supports tcp and websockets, and apart from that provides the option to upgrade a
connection with protocols for multiplexing and authentication. 

The second important concept of libp2p is its `Swarm` (in newer implementations and documents also called `Switch`).
The swarm is responsible for negotiating protocols, managing transports and sending and receiving messages via different
protocols. It is possible to combine different protocols into a so called `NetworkBehaviour`, which is what this library is doing.
Stronghold-communication uses multicast DNS (mDNS) for peer discovery in a local network and the RequestResponse protocol in order to send / receive
custom messages and parse them. 

## Multiplexing and Noise-encryption

The transport of stronghold-communication is upgraded with yamux for multiplexing and the noise protocol, this noise protocol uses the XX-Handshake and ensures authentification and encryption.

## Stronghold-Communication

Similar to the swarm in libp2p, the stronghold-communication creates the `P2PNetworkBehaviour` struct that manages sending messages and reacting upon the outcome of the operation. 
Upon creating a new instance, a transport is created and upgraded, and combined with a the P2PNetworkBehaviour into a ExpandedSwarm. This Swarm is returned to the caller and serves as entrypoint for all communication to other peers. It implements methods for listening to the swarm, sending outbound messages, and manually adding and dialing peers. Incoming `P2PEvent` can be handled by polling from the swarm, e.g. via the `poll_next_unpin` method. 
Due to libp2ps concept of `multiaddresses`, the swarm has multiple listening addresses that encode different addressing schemes for different
protocols. Apart from IPv4 and IPv6 Addresses, these multiaddresses can also be dns addresses, which is relevant if a peer is listening
to such an address on a server. The listed multiaddresses are only the ones within the same local network, but if port forwarding was configured,
the local /ip4/my-local-address/tcp/12345 Address can be replaced by the public one or by `/dns/my.public.server.address/tcp/12345`, where the 
`/tcp/12345` part describes the port.

## Mailbox Concept

Since not all peers can be dialed directly e.g. because they are behind a firewall, stronghold-communication includes methods for using
a mailbox. The mailbox is a peer running on a server with public IP Address that can be reached by all other peers. If can be
used to deposit records for unavailable remote peers by sending a `Request::PutRecord` message with the record to the mailbox, and that can then return the Records to remote peers upon receiving a `Request::GetRecord` request.
