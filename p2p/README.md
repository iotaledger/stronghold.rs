# Stronghold Peer-to-Peer Communication

The Stronghold-p2p library enables end-to-end encrypted communication between peers in different processes, devices and networks.
The basis for its functionality is the [libp2p](https://libp2p.io/) framework, which is a system of protocols, specifications and libraries that enable the development of peer-to-peer network applications.

You can build the Stronghold-p2p crate separately from Stronghold, as well as use it independently. It allows users to transmit generic 1:1 Request-Response messages between two peers, with an additional firewall that prevents unauthorized access. In case that a peer may not be dialed directly, it supports the usage of a relay peer that blindly relays the traffic between two peers.

## Transmission of Data

Data is transmitted via a [TCP](https://en.wikipedia.org/wiki/Transmission_Control_Protocol) transport with additional support for [Websockets](https://en.wikipedia.org/wiki/WebSocket) and [DNS](https://en.wikipedia.org/wiki/Domain_Name_System) resolution.
The transport is "upgraded" with the [Yamux Protocol](https://github.com/hashicorp/yamux/blob/master/spec.md) for multiplexing, and a [Noise](https://noiseprotocol.org/noise.html) protocol that implements end-to-end encryption. 

The Noise-handshake is based on the [Diffie-Helllman key exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) and allows two peers that have no prior knowledge of each other to create a shared secret key over an insecure medium. Stronghold-p2p uses the [XX-Pattern](http://noiseprotocol.org/noise.html#interactive-handshake-patterns-fundamental) for the handshake.

## Connecting Peers

A peer can establish a connection to a remote peer if they know the remote peer's address. If both peers are in the same local network, they can enable the [`Mdns`](https://en.wikipedia.org/wiki/Multicast_DNS) feature, which implements automatic peer discovery in a local network.

If the two peers are in two different networks without public IP addresses, Stronghold-p2p supports the usage of relay peers. The relay forwards all traffic between source and destination. Thanks to the Noise-encryption, the communication is end-to-end encrypted between the two peers, independently of whether a relay is used or not.

## Firewall

Stronghold-p2p's network protocol implements a low-level firewall. The firewall approves or rejects each inbound and outbound request based on default and peer-specific rules. In addition to fixed rules, requests may also be approved or rejected individually in an asynchronous manner.
