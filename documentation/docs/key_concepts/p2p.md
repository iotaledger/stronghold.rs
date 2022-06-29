---
description: Stronghold peer to peer communication 
image: /img/logo/Stronghold_icon.png
keywords:
- p2p
- networking
---

# Stronghold peer to peer communication

#### Authors: Matthias Kandora - \<matthias.kandora@iota.org>


Stronghold comes with extensive communication features as well. On the surface level there are two modes of operations: 

- Run Stronghold as a server to provide services on sensitive data like remote procedure execution
- Run Stronghold as relay, some intermediary to connect peers, if not peer to peer connection is directly possible. ( At the time of writing, all peer to peer connections are currently routed through the relay, but this restriction will be lifeted in the future).

Use the first mode, if you need some kind of server-client setup. Think of some kind of remote security module, where you can sign messages, export public keys etc. Use the second mode to synchronize data between two Strongholds. 

The peer to peer capabilities are built on top of libp2p, the foundation of ipfs.Communication between two Strongholds is secured by the underlying implementation of the NOISE protocol. In short, at the beginning two Strongholds are exchanging handshake messages. Each participant generates a keypair (eg. Ed25519), exchanges diffie-helman public keys, operates on ephemeral keys and hashing the results into a shared secret.  The shared secret is then being used to send encrypted transport messages. 

Stronghold makes use of static keys, and ephemeral keys, which will be used for the handshake protocol and the encrypted transport. The handshake pattern being used for secret exchange is being designed as XX. where the first X describes the static key transmitted to the responder, while the second describes the static key for responder transmitted by initiator. See the protocol website or in-depth explanation, on how the NOISE protocol works.

Each incoming connection is secured by a simple application level firewall. Rules can be defined for each peer trying to access certain parts of a Stronghold. Eg. the firewall can be configured, that only certain paths are available to a remote requesting peer.

Strongholds running as remote Instances are being addressed with the multiaddr format.