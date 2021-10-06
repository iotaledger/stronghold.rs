# Stronghold Peer-to-Peer Communication

The Stronghold-p2p library enables end-to-end encrypted communication between peers in different processes, devices and networks.
The basis for its functionality is the [libp2p](https://libp2p.io/) framework, which is a system of protocols, specifications and libraries that enable the development of peer-to-peer network applications.

The crate is build separately of Stronghold, and may be used independently. It allows the user to transmit generic 1:1 Request-Response messages between two peers, with an additional firewall to prevent unauthorized access. In case that a peer may not be dialed directly, it optionally supports the usage of relay peer that blindly relays the traffic between two peers.

## Transmission of Data

The data is transmitted via a TCP transport with additional support for Websockets and DNS resolution.
The transport is "upgraded" with the [Yamux Protocol](https://github.com/hashicorp/yamux/blob/master/spec.md) for multiplexing, and a [Noise](https://noiseprotocol.org/noise.html) protocol that implements end-to-end encryption. The Noise-handshake is based on the Diffie-Helllman key exchange and allows two peers, that have no prior knowledge of each other, to create a shared secret key over an insecure medium. In case of Stronghold-p2p, the XX-Pattern is used for the handshake.

## Connecting Peers

A peer can establish a connection to a remote one if they know the remote's address. If both peers are in the same local network, the `Mdns` feature can be enabled, which implements automatic peer discovery in a local network.
If the two peers are in two different network without public IP-addresses, Stronghold-p2p support the usage of relay peers. The relay forwards all traffic between source and destination. Due to the Noise-encryption, the communication is nonetheless end-to-end encrypted between the two peers, independently of whether a relay is used or not.

## Firewall

The network-protocol of Stronghold-p2p implements a low level firewall. The firewall approves/ rejects each inbound and outbound request based on default, and peer-specific rules. In a addition to fixed rules, requests may also be approved/ rejected individually in an asynchronous manner.
