# Changelog

## \[0.4.0]

- Updated cargo.toml files with the updated crypto.rs revisions and authors.
  Fixed logic in snapshot and providers to use the `try_*` encryption and decryption functions.
  Fixed commandline and stopped it from overwriting snapshots.
  - [64e08fe](https://www.github.com/iotaledger/stronghold.rs/commit/64e08fe39454d2191561783d009b155c91db37c1) add .changes. on 2021-03-19
  - [0758b67](https://www.github.com/iotaledger/stronghold.rs/commit/0758b6734a1e22d491345a6b894acea12ab5b1b7) add .changes. on 2021-03-19
- Remove old logic from client and vault.
  Added clear cache logic and message to stop the client actor.
  Removed Client Derive Data hashmap.
  - [81892aa](https://www.github.com/iotaledger/stronghold.rs/commit/81892aa704b920c50de2517e8073943d8bf0c2b9) add md file. on 2021-04-20
- Add libp2p-relay protocol to stronghold-communication.
  Add methods for using a relay peer to the iota-stronghold interface.
  - [a414582](https://www.github.com/iotaledger/stronghold.rs/commit/a414582024f45e854a75ab82e4196777ab4a42b8) Feat/comms relay ([#183](https://www.github.com/iotaledger/stronghold.rs/pull/183)) on 2021-04-13
- move stronghold-utils and add utils-derive for proc macros.
  rebuild vault and remove versioning.
  update client to use new vault.
  - [5490f0a](https://www.github.com/iotaledger/stronghold.rs/commit/5490f0aaaf58e5322a5569c02669514ec067b02f) refactor vault ([#181](https://www.github.com/iotaledger/stronghold.rs/pull/181)) on 2021-04-15

## \[0.3.0]

- Rename the previously incorrectly named combined SLIP10+Ed25519 procedures (now
  named with a `SLIP10DeriveAnd` prefix) and add back the Ed25519 ("only")
  procedures.
  - [e221dcb](https://www.github.com/iotaledger/stronghold.rs/commit/e221dcb31519960e60982012da3c2ac154d989e1) Add back the atomic Ed25519 procedures ([#122](https://www.github.com/iotaledger/stronghold.rs/pull/122)) on 2021-01-08
  - [8e255bf](https://www.github.com/iotaledger/stronghold.rs/commit/8e255bf4aad8caf69dcddfac24d4cdb07f716177) fix(covector): wrong version bump type ([#128](https://www.github.com/iotaledger/stronghold.rs/pull/128)) on 2021-01-14
- Add documentation and cleanup the code for these crates and modules in preparation for beta.
  - [dae0457](https://www.github.com/iotaledger/stronghold.rs/commit/dae04579cb20ad69a7aecdf102fb66ecac4aaf46) Beta Cleanup ([#166](https://www.github.com/iotaledger/stronghold.rs/pull/166)) on 2021-03-19
- Change the communication firewall configuration, add new methods for it to the client interface.
  Cleanup the stronghold-communication code, add documentation and examples.
  - [b9d006c](https://www.github.com/iotaledger/stronghold.rs/commit/b9d006cef88f6ae45f47a8644702a800d13e39c5) Feat/communication cleanup ([#167](https://www.github.com/iotaledger/stronghold.rs/pull/167)) on 2021-03-18
- Implement a configurable firewall in the communication actor, add a macro to derive permissions for requests.
  - [025685f](https://www.github.com/iotaledger/stronghold.rs/commit/025685fb181ba0600f31680a3f4c115c0e2097f7) Feat/communication firewall ([#158](https://www.github.com/iotaledger/stronghold.rs/pull/158)) on 2021-03-11
- Refactor the communication actor, enable using a relay peer, and integrate communication as feature into the stronghold interface.
  Remove unecessary Option/ Result wraps in `random` and `iota-stronghold`.
  Rename stronghold-test-utils to stronghold-utils and added riker ask pattern to it.
  - [9c7cba6](https://www.github.com/iotaledger/stronghold.rs/commit/9c7cba624e2a99f04a2d033b8673f8a4b8735f0b) Feat/integrate comms ([#130](https://www.github.com/iotaledger/stronghold.rs/pull/130)) on 2021-02-26
  - [fcb62bb](https://www.github.com/iotaledger/stronghold.rs/commit/fcb62bbf966bfcd543b13a79d73839a3fee0219e) fix/covector-2 ([#163](https://www.github.com/iotaledger/stronghold.rs/pull/163)) on 2021-03-12
- Remove Crypto, Random and Primitives libraries in favor of Crypto.rs
  Moved Runtime into the engine.
  Add new guarded types for Runtime and remove old logic.

## Features:

- Causes segfault upon access without borrow
- Protects using mprotect
- Adds guard pages proceeding and following the allocated memory.
- Adds a canary pointer to detect underflows.
- Locks memory with mlock.
- Frees memory using munlock
- Memory is zeroed when no longer in use through sodium_free
- Can be compared in constant time
- Can not be printed using debug
- Can not be cloned using the Clone trait.

Implement guarded types in Vault to protect the data and the keys.
Clean up logic inside of the Client library.

- [dd65b67](https://www.github.com/iotaledger/stronghold.rs/commit/dd65b67f42718150c7c7dbab9606ee2167cf11ce) add changes. on 2021-03-11
- [829ecac](https://www.github.com/iotaledger/stronghold.rs/commit/829ecac2e8090d478706c673cd45f1b91a60b2de) fix(covector) ([#164](https://www.github.com/iotaledger/stronghold.rs/pull/164)) on 2021-03-12
- Add `Clone`/`Debug` implementations for `StrongholdFlags` and `VaultFlags`.
  - [e9fda48](https://www.github.com/iotaledger/stronghold.rs/commit/e9fda4859d0367f3a69265dcb5d4d276bfb07066) Add Clone/Debug implementations for StrongholdFlags/VaultFlags ([#157](https://www.github.com/iotaledger/stronghold.rs/pull/157)) on 2021-03-12

## \[0.2.0]

- Added the initial client logic and integrated it with the Riker actor model. Change includes a Client/Cache actor, a Bucket actor, a Snapshot actor, and a keystore actor.  All of the Stronghold APIs are available.
  - [7c7320a](https://www.github.com/iotaledger/stronghold.rs/commit/7c7320ab0bc71749510a590f418c9bd70329dc02) add client changelog. on 2020-11-30
  - [4986685](https://www.github.com/iotaledger/stronghold.rs/commit/49866854f32dde8589f37c6d9ea0c2e7ddb3c461) remove todos and update readme. on 2020-11-30
  - [7f1e9ed](https://www.github.com/iotaledger/stronghold.rs/commit/7f1e9edf5f5c5e148376575057a55d1d1398708a) Chore/covector fix ([#61](https://www.github.com/iotaledger/stronghold.rs/pull/61)) on 2020-12-01
  - [f882754](https://www.github.com/iotaledger/stronghold.rs/commit/f88275451e7d3c140bbfd1c90a9267aa222fb6d0) fix(client): readme and changelog ([#64](https://www.github.com/iotaledger/stronghold.rs/pull/64)) on 2020-12-01
- Create SignUnlockBlock procedure.
  - [f9d180a](https://www.github.com/iotaledger/stronghold.rs/commit/f9d180a85fe57c2942d6ebabfcfdb3c445b0ba5b) feat(client): introduce SignUnlockBlock proc ([#92](https://www.github.com/iotaledger/stronghold.rs/pull/92)) on 2020-12-21
- Alpha release of Stronghold: "Saint-Malo"
  - [4b6f4af](https://www.github.com/iotaledger/stronghold.rs/commit/4b6f4af29f6c21044f5063ec4a8d8aff643f81a7) chore(release) ([#105](https://www.github.com/iotaledger/stronghold.rs/pull/105)) on 2020-12-24
  - [06c6d51](https://www.github.com/iotaledger/stronghold.rs/commit/06c6d513dfcd1ba8ed6379177790ec6db28a6fea) fix(changelog): Alpha Release ([#106](https://www.github.com/iotaledger/stronghold.rs/pull/106)) on 2020-12-24
- Introduce release manager for rust crates including tangle registry.
  - [c10811e](https://www.github.com/iotaledger/stronghold.rs/commit/c10811effbff396370762e76a2f2d44221dc7327) feat(covector): rigging ([#57](https://www.github.com/iotaledger/stronghold.rs/pull/57)) on 2020-11-29
- Add a hierarchical wallet implementation following SLIP10 for the Ed25519 curve.
  - [dd12c16](https://www.github.com/iotaledger/stronghold.rs/commit/dd12c16d628ec996728d356cfb815f185cc5cc37) Add changelog message on 2020-12-02
  - [d3c63be](https://www.github.com/iotaledger/stronghold.rs/commit/d3c63bec8052c0cd6a636fef3463b90893b55d4b) fix(covector) ([#82](https://www.github.com/iotaledger/stronghold.rs/pull/82)) on 2020-12-17
