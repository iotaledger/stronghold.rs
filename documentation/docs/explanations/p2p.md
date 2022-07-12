---
description: Stronghold peer to peer communication 
image: /img/logo/Stronghold_icon.png
keywords:
- p2p
- networking
- explanation
---

# Peer to Peer Communication in Stronghold

Stronghold includes extensive communication features. At surface level, there are two modes of operations:

1. You can run Stronghold as a server to provide services on sensitive data like remote procedure execution
2. You can run Stronghold as a relay, some intermediary to connect peers. If not peer to peer connection is directly possible.

At the time of writing, all peer to peer connections are currently routed through the relay, but this restriction will be lifted in the future.

If you need some kind of server-client setup, you should use the first mode. Think of a remote security module where you can sign messages, export public keys, etc. You should use the second mode to synchronize data between two Strongholds.

The peer to peer capabilities are built on top of libp2p, the foundation of IPFS. Communication between two Strongholds is secured by the underlying implementation of the NOISE protocol. In short, in the beginning, two Strongholds exchange handshake messages. Each participant generates a key pair (e.g., Ed25519), exchanges [Diffie-Helman](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) public keys, operates on ephemeral keys and hashes the results into a shared secret. The shared secret is later used to send encrypted transport messages.

Stronghold uses static and ephemeral keys for the handshake protocol and encrypted transport. The handshake pattern used for secret exchange is designed as XX. The first X describes the static key transmitted to the responder, while the second describes the static key for the responder sent by the initiator.

:::note Noise Protocol

You can find a detailed explanation of how the NOISE protocol works on the official [NOISE Protocol website](http://www.noiseprotocol.org/).

:::

A simple application level firewall secures each incoming connection. You can define rules for each peer trying to access certain parts of a Stronghold. For example, you can configure the firewall so only certain paths are available to a remote peer.

Remote instances of Stronghold are being addressed with the [multiaddr format](https://multiformats.io/multiaddr/).