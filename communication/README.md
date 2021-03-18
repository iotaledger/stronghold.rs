# Stronghold Communication

This library enables strongholds on different devices and in different networks to communicate with each other.
The main basis for its functionality is the [rust-libp2p](https://github.com/libp2p/rust-libp2p) library, which is a system of protocols, specifications and libraries that enable the development of peer-to-peer network applications (https://libp2p.io/).


## Network Behaviour and Swarm

**module behaviour.rs:**

Stronghold-communication implements the `P2PNetworkBehaviour` for sending messages and reacting upon the outcome of the operation. 
It combines multiple protocols of Libp2p:
- Multiplexing following the [Yamux specification](https://github.com/hashicorp/yamux/blob/master/spec.md)  
- Noise: Encryption of the communication using the [Noise protocol](https://noiseprotocol.org/noise.html) with XX-Handshake
- Multicast DNS: Enable Peer Discovery in a local network
- Identify Protocol: Receive identifying information like the `PeerId` and listening addresses when connecting to a new peer.
- Request-Response Protocol: Allows sending direct request/response messages between Peers; it expects a response for each request
 
Upon creating a new instance, a transport is created and upgraded, and combined with the P2PNetworkBehaviour into a [ExpandedSwarm](https://docs.rs/libp2p/0.35.1/libp2p/swarm/struct.ExpandedSwarm.html). This Swarm is returned to the caller and serves as entry-point for all communication to other peers. Additional to the Libp2p methods of the `ExpandedSwarm`, it enables sending outbound messages, and manages the known peers. Incoming `P2PEvents` can be handled by polling from the swarm, e.g. via the `next` method.   


## Communication Actor

**module actor.rs:**

The `Communication Actor` is using the [Riker Framwork](https://riker.rs/) to implement the actor pattern.  
When creating a new `Communication Actor`, the actor creates a `P2PNetworkBehaviour` and continuously polls for events,
incoming requests are sent to the client actor that has to be provided in the `CommunicationConfig`.

All swarm interaction, and configuration of the `Communication Actor` is accomplished by sending the appropriate `CommunicationRequest` to it, for each `CommunicationRequest` a `CommunicationResults` is returned to the sender, this also allows using the [ask pattern](https://riker.rs/patterns/#ask).

### Firewall
The communication actor implements a firewall that checks the permission of each outgoing and incoming requests and drops them if the necessary permission has not been set. The required `ToPermissionVariants` trait for messages can be derived with the [communication-macros](communication-macros/README.md), this allows in case of enum Request types to accept specific variants while rejecting others.




