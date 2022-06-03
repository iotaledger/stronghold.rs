# Changelog

## \[0.5.1]

- bump all crate versions to update to new utils modules
  - [29ad7932](https://www.github.com/iotaledger/stronghold.rs/commit/29ad7932550ec558915ec88c7f26408dd2c763e7) version: bump all crates to include updated utils on 2022-06-03
  - [699117f7](https://www.github.com/iotaledger/stronghold.rs/commit/699117f7ea834c043596418f8ff2c502c477bf6b) version: bump all crates to include updated utils on 2022-06-03
  - [34ada641](https://www.github.com/iotaledger/stronghold.rs/commit/34ada641a6ac987e9c17d8d71581a5083bd61911) fix: covector fixx crate name on 2022-06-03
  - [092ce898](https://www.github.com/iotaledger/stronghold.rs/commit/092ce898a31440e4d5740f40952fbf711da8ce02) fix: covector fixx crate name on 2022-06-03
  - [f01e99e3](https://www.github.com/iotaledger/stronghold.rs/commit/f01e99e319f286f2b094ee9efe88cf44a638fa45) version: reset to former versions on 2022-06-03
  - [b441e6f4](https://www.github.com/iotaledger/stronghold.rs/commit/b441e6f476571f067cdddd93c9ae8370d59733ba) fix: versions on 2022-06-03

## \[0.5.1]

- bump all crate versions to update to new utils crate
  - [29ad7932](https://www.github.com/iotaledger/stronghold.rs/commit/29ad7932550ec558915ec88c7f26408dd2c763e7) version: bump all crates to include updated utils on 2022-06-03
  - [699117f7](https://www.github.com/iotaledger/stronghold.rs/commit/699117f7ea834c043596418f8ff2c502c477bf6b) version: bump all crates to include updated utils on 2022-06-03
  - [34ada641](https://www.github.com/iotaledger/stronghold.rs/commit/34ada641a6ac987e9c17d8d71581a5083bd61911) fix: covector fixx crate name on 2022-06-03
  - [092ce898](https://www.github.com/iotaledger/stronghold.rs/commit/092ce898a31440e4d5740f40952fbf711da8ce02) fix: covector fixx crate name on 2022-06-03

## \[0.5.1]

- bump version
  - Bumped due to a bump in stronghold-utils.
  - [8548949b](https://www.github.com/iotaledger/stronghold.rs/commit/8548949b691ed85ec9140f28fc7eff11126916b3) version: bump utils on 2022-06-02
  - [96d895ae](https://www.github.com/iotaledger/stronghold.rs/commit/96d895aea09504d146176dd5b878e6144a01f1ae) apply version updates on 2022-06-02
  - [f5e8a7a8](https://www.github.com/iotaledger/stronghold.rs/commit/f5e8a7a80fc9e7b16a8974f2905fe1cfb4d645f2) version: fix utils version; enable bump on 2022-06-02
  - [c3757950](https://www.github.com/iotaledger/stronghold.rs/commit/c3757950fc1cd3b16167512584bfe89c5c50ffa6) apply version updates on 2022-06-02
  - [a6524545](https://www.github.com/iotaledger/stronghold.rs/commit/a6524545088fbf02ac013e47a80c0bf3e987c481) version: reset all versions; bump utils on 2022-06-02

## \[0.5.2]

- bump version
  - Bumped due to a bump in stronghold-utils.
  - [8548949b](https://www.github.com/iotaledger/stronghold.rs/commit/8548949b691ed85ec9140f28fc7eff11126916b3) version: bump utils on 2022-06-02
  - [96d895ae](https://www.github.com/iotaledger/stronghold.rs/commit/96d895aea09504d146176dd5b878e6144a01f1ae) apply version updates on 2022-06-02
  - [f5e8a7a8](https://www.github.com/iotaledger/stronghold.rs/commit/f5e8a7a80fc9e7b16a8974f2905fe1cfb4d645f2) version: fix utils version; enable bump on 2022-06-02

## \[0.5.1]

- bump
  - Bumped due to a bump in stronghold-utils.
  - [8548949b](https://www.github.com/iotaledger/stronghold.rs/commit/8548949b691ed85ec9140f28fc7eff11126916b3) version: bump utils on 2022-06-02

## \[0.5.0]

- bump version
  - [b72f9fda](https://www.github.com/iotaledger/stronghold.rs/commit/b72f9fdaf68062dfcbc05155842f216649715ab5) fix: remove bindings from workspace dependencies on 2022-06-02
  - [c9247092](https://www.github.com/iotaledger/stronghold.rs/commit/c9247092dfd9a95b926b66e06fdb3a0a4a3300a1) fix: package name on 2022-06-02

## \[0.6.0]

- Fix package description
  - [b6e6977a](https://www.github.com/iotaledger/stronghold.rs/commit/b6e6977aba951c60d26ad7ef756719a93f8e5b95) fix: package description on 2022-06-02

## \[0.5.0]

- Bump
  - [6f1c160a](https://www.github.com/iotaledger/stronghold.rs/commit/6f1c160a3182f136868406bdca99022efd45dd67) Fix versions for covector on 2022-06-01

## \[0.6.0]

- - Refactor Sink and Stream implementation for EventChannel
- Add `CopyRecord` procedure.
- In the `StrongholdP2p` Interface enable / disable mdns and relay functionality on init via config flags in the `StrongholdP2pBuilder`. Per default, both are enabled.
- In the `Stronghold` client interface enable / disable mdns and relay in the `NetworkConfig` when spawning a new p2p-network actor. Per default, both are disabled.
- Use `libp2p::swarm::toggle` to enable/ disable relay and mdns
- Persist config and keypair of stronghold-p2p in client
- Implement messages to write the keypair used for `StrongholdP2p` in the vault and derive the `PeerId` and a new noise `AuthenticKeypair` from it.
- Implement API for the Stronghold Procedures
- Make stronghold interface clonable
- Update inline Docs and README files to reflect the current state of the project.
- Add communication fuzzer for distributed fuzzing with docker.
- Patch Stronghold engine fuzzer.
- Patch crypto.rs version v0.7 -> v0.8.
- Persist the state of stronghold-p2p in the `SecureClient` by serializing the `NetworkConfig` and writing it to the store.
- Allow loading stored states into the `NetworkActor` on init.
- Allow reuse of same `Keypair` that is stored in the vault.
- Software transactional memory framework as replacement for actix actor system
- Integration is runtime agnostic an can be used by any async runtime for rust, tkio is encouraged though
- Extract `random` functions from `test_utils` into own module.
- Remove Riker as dependency from utils.
- Introduce KeyProvider instead of repeatedly providing a passphrase.
- Introduce non-contiguous memory types for secure key handling.
- Abstract over locked and encrypted data types for use internally.
- Stronghold interface rewrite to work on type level with Stronghold as root type, Client as secure container, Store as insecure storage and ClientVault as vault access.
- [3816aef5](https://www.github.com/iotaledger/stronghold.rs/commit/3816aef5111684ffbdbd12ed7f93b887e43e7a02) chore(release-doc): clean up outdated release notes, merge existing into one on 2022-05-31
- [40079275](https://www.github.com/iotaledger/stronghold.rs/commit/4007927585bba598055bfd6538f36060828b1a8d) apply version updates on 2022-06-01
- [31358c04](https://www.github.com/iotaledger/stronghold.rs/commit/31358c04fc7054087da3bed4d0dbfc39b0817263) fix: enforce Stronghold version update on 2022-06-01

## \[0.5.0]

- - Refactor Sink and Stream implementation for EventChannel
- Add `CopyRecord` procedure.
- In the `StrongholdP2p` Interface enable / disable mdns and relay functionality on init via config flags in the `StrongholdP2pBuilder`. Per default, both are enabled.
- In the `Stronghold` client interface enable / disable mdns and relay in the `NetworkConfig` when spawning a new p2p-network actor. Per default, both are disabled.
- Use `libp2p::swarm::toggle` to enable/ disable relay and mdns
- Persist config and keypair of stronghold-p2p in client
- Implement messages to write the keypair used for `StrongholdP2p` in the vault and derive the `PeerId` and a new noise `AuthenticKeypair` from it.
- Implement API for the Stronghold Procedures
- Make stronghold interface clonable
- Update inline Docs and README files to reflect the current state of the project.
- Add communication fuzzer for distributed fuzzing with docker.
- Patch Stronghold engine fuzzer.
- Patch crypto.rs version v0.7 -> v0.8.
- Persist the state of stronghold-p2p in the `SecureClient` by serializing the `NetworkConfig` and writing it to the store.
- Allow loading stored states into the `NetworkActor` on init.
- Allow reuse of same `Keypair` that is stored in the vault.
- Software transactional memory framework as replacement for actix actor system
- Integration is runtime agnostic an can be used by any async runtime for rust, tkio is encouraged though
- Extract `random` functions from `test_utils` into own module.
- Remove Riker as dependency from utils.
- Introduce KeyProvider instead of repeatedly providing a passphrase.
- Introduce non-contiguous memory types for secure key handling.
- Abstract over locked and encrypted data types for use internally.
- Stronghold interface rewrite to work on type level with Stronghold as root type, Client as secure container, Store as insecure storage and ClientVault as vault access.
- [3816aef5](https://www.github.com/iotaledger/stronghold.rs/commit/3816aef5111684ffbdbd12ed7f93b887e43e7a02) chore(release-doc): clean up outdated release notes, merge existing into one on 2022-05-31
