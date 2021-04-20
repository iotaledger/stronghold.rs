![banner](./.meta/stronghold_beta.png)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fiotaledger%2Fstronghold.rs.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fiotaledger%2Fstronghold.rs?ref=badge_shield)

[![status](https://img.shields.io/badge/Status-Beta-green.svg)](https://github.com/iotaledger/stronghold.rs)
![Audit](https://github.com/iotaledger/stronghold.rs/workflows/Audit/badge.svg?branch=dev)
![Test](https://github.com/iotaledger/stronghold.rs/workflows/Test/badge.svg)
[![docs](https://img.shields.io/badge/Docs-Official-red.svg)](https://stronghold.docs.iota.org)
[![coverage](https://coveralls.io/repos/github/iotaledger/stronghold.rs/badge.svg?branch=dev)](https://coveralls.io/github/iotaledger/stronghold.rs?branch=dev)
[![dependency status](https://deps.rs/repo/github/iotaledger/stronghold.rs/status.svg)](https://deps.rs/repo/github/iotaledger/stronghold.rs)

## Introduction
[summary]: #summary

**IOTA Stronghold** is a secure software implementation with the sole purpose of isolating digital secrets from exposure to hackers and accidental leaks. It uses encrypted snapshots that can be easily backed up and securely shared between devices. Written in stable rust, it has strong guarantees of memory safety and process integrity. 

There are four main components of Stronghold:
1. **Client**: The high-level interface to Stronghold (prefers Riker, functional integration also available)
2. **Engine**: Combines a persistence store (Snapshot) with an in-memory state interface (Vault), a read/write key:value system (Store) and memory protection services (Runtime).
3. **Communication**: Enables Strongholds in different processes or on different devices to communicate with each other securely.

## WARNING
These libraries have been reviewed internally and are being prepared for a full external security audit in mid 2021, so they are not yet verifiably safe. Until this warning is removed, the IOTA Foundation makes no guarantees to the fitness of these libraries for use by third parties.

Nevertheless, we are very interested in feedback about the design and implementation, and encourage you to reach out with any concerns or suggestions you may have.

## Roadmap
Here are some of the features and tasks that we are working on.


#### Components
- [x] Engine
- [x] Client (with dual interfaces)
- [x] peer-to-peer communications
- [x] Secure runtime zone 
- [x] Integration with crypto.rs 

### Documentation and Specification
- [ ] User Handbooks
- [ ] Specification Documentation
- [ ] Tutorials

### Performance and Testing
- [x] Unit Tests
- [x] Lowlevel Library Fuzzing
- [ ] Realworld tests
- [x] Multiplatform benchmarks
- [ ] Continuous Fuzzing

#### Applications
- [x] CLI binary
- [ ] Standalone Desktop Application
- [ ] Portable Daemon (for nodes, etc)
- [ ] Dynamic high-performance store 
- [ ] C FFI bindings

### Hardware Integrations
- [x] Works with USB Armory Mk II
- [ ] Works with Yubikey
- [ ] Works with Ledger Nano X
- [ ] Use Secure Element to generate private keys for decryption
- [ ] Move entirely to FPGA

## API Reference
### RUSTDOCS
- [client](https://stronghold.docs.iota.org/docs/iota_stronghold/index.html)
- [engine](https://stronghold.docs.iota.org/docs/stronghold_engine/index.html)
- [communication](https://stronghold.docs.iota.org/docs/stronghold_communication/index.html)

### Do it yourself
```
cargo doc --workspace --no-deps --open
```
## Running Tests
```
cargo test --all --all-features
```

## Joining the discussion
If you want to get involved in discussions about this technology, or you're looking for support, go to the #stronghold-discussion channel on [Discord](https://discord.iota.org/).

If you wish to join the Stronghold X-Team, please fill out [this form](https://forms.gle/AUdjcp4kCRLgG3Qd9).

## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fiotaledger%2Fstronghold.rs.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fiotaledger%2Fstronghold.rs?ref=badge_large)