---
slug: /overview
---

# Overview

IOTA Stronghold is a secure software implementation with the sole purpose of isolating digital secrets from exposure to hackers and accidental leaks. It uses encrypted snapshots that can be easily backed up and securely shared between devices. Written in stable rust, it has strong guarantees of memory safety and process integrity.

There are four main components of Stronghold:

1. [**Client**](./structure/client.md): The high-level interface to Stronghold (prefers Riker, functional integration also available)
2. [**Engine**](./structure/engine.md): Combines a persistence store (Snapshot) with an in-memory state interface (Vault) and a key:value read/write (Store).
3. [**Runtime**](./structure/runtime.md): Is a process fork with limited permissions within which cryptographic operations take place.
4. [**Communication**](./structure/communication.md): Enables Strongholds in different processes or on different devices to communicate with each other securely.

Read more about the [Alpha Release](https://blog.iota.org/stronghold-alpha-release/).

Read more about the [Beta Release](https://blog.iota.org/iota-stronghold-beta-release/).
