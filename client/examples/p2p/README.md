# Stronghold P2P-Network Example

The network examples show the p2p-networking capabilities of stronghold.
Some are just "one-shot" examples to show what is possible with stronghold in an easy way

## Quickstart

Run following command to show sample output for the network example:

```sh
cargo run --features p2p p2p
```

This will display some helpful output

```sh
Stronghold Example P2P-Network 
Example to show stronghold's p2p-networking capabilities

USAGE:
    comm [actor-path] <SUBCOMMAND>

ARGS:
    <actor-path>    [default: actor_path]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    help          Prints this message or the help of the given subcommand(s)
    listen        Start listening on multiaddress.
    peers         Lists all peers.
    relay         Relay traffic to a peer.
    swarm-info    Displays information on this node
```

## Listen for connections

To start stronghold to listen for remote peer connections, you can run

```no_run
cargo run --features p2p --example p2p listen --multiaddr "/ip4/127.0.0.1/tcp/7001"
```

## Show swarm info

To show info on neighbouring peers you can run

```no_run
cargo run --features p2p --example p2p swarm-info
```

## Add Peer(s)

Peers can also be added by running

```no_run
cargo run --features p2p --example p2p
```
