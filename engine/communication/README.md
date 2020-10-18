# communication
Basic Mailbox that enables different peers to communicate with each other.

In order to provide a message / record for a remote peer, a local peer adds this information to a key-value-store mailbox that runs on a server. The mailbox publishes this record in their kademlia DHT, from which the remote peer can then read the value if they know the key.

## Getting started

` cargo run`

optional arguments: 
- `--port <port>` to set a port that this peer listens to within the same network, default is randomly assigned by the OS
- `--mailbox <mailbox-multiaddress> <mailbox-peerid>` to connect to a mailbox, the arguments should be entered within string quotes.

## command line interface

All values shoul be entered within typical string-quotes, apart from the expire_sec, which is a numeric value without quotes.
- `LIST`: list all the entries within the kademlia bucket of the peer
- `PING <ping_id>` Ping a remote peer in order to test the connection. This only works with peers that has been discovered and are listed in the kademlia bucket
- `GET <key>` Get the stored key-value pair for this key from either the own kademlia store or from the mailbox. Keys have to be alphanumeric.
- `PUT <key> <value> <expire_sec:OPTIONAL>` Add a record to the mailbox, key should be alphanumeric, values may contain any chars apart from '"'. The optional expire_sec should be a numeric value and it describes the duration that this record is available on the mailbox. If no expire is given, it will be the default value of 90000sec/15min.

## libp2p protocols

- libp2p-noise for authentication
- libp2p-kademlia DHT for peer discovery and publishing / reading records
- libp2p-mdns for peer discovery within a local network
- implementation of the libp2p-request-response protocol for custom Request/Response Messages


