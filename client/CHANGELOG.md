# Changelog

## \[1.1.0]

- Bump `iota-crypto` version to 0.18.0. `Pbkdf2Hmac::count` changed to a `NonZeroU32`.
  - [a860896c](https://www.github.com/iotaledger/stronghold.rs/commit/a860896c56a3ebae2bef9ffb37e3effff074fa79) Bump crypto on 2023-05-03
  - [03ff2dcd](https://www.github.com/iotaledger/stronghold.rs/commit/03ff2dcd59326b923d319b7ee33224091db838b6) better changelog on 2023-05-03
  - [74e564d2](https://www.github.com/iotaledger/stronghold.rs/commit/74e564d2d76624e267d85c02ac3a6eca1bc1af32) even more betterer changelog on 2023-05-03
  - [6d32ae45](https://www.github.com/iotaledger/stronghold.rs/commit/6d32ae4549c02989b6d68b15f8536bb8374c40a4) remove native on 2023-05-03

## \[1.0.5]

- Disable frag module for android and ios targets.
  - [0a2331a9](https://www.github.com/iotaledger/stronghold.rs/commit/0a2331a906493c3466f029155601aa0cda8f363d) Fix clippy and add covector changefile on 2022-11-14
  - [21fbdc68](https://www.github.com/iotaledger/stronghold.rs/commit/21fbdc68dbee1e803be1ed214e0e1f98ebffe711) Add changefiles on 2022-11-15
  - [4561e4a9](https://www.github.com/iotaledger/stronghold.rs/commit/4561e4a93e2c7119e5da04c1eb5b505303bb3114) Merge changefiles on 2022-11-15

## \[1.0.4]

- fix typos in `ClientError`
  - [8dd5799b](https://www.github.com/iotaledger/stronghold.rs/commit/8dd5799b8e1e6b88bf7a9cd0313b760b00b6f740) Rename Typos.md to typos.md on 2022-10-24

## \[1.0.3]

- update version of zeroize
  - [5eba6e8c](https://www.github.com/iotaledger/stronghold.rs/commit/5eba6e8cc77caeb30e1259c90518a03226212877) update zeroize on 2022-10-19

## \[1.0.2]

- Update dependencies to pull version 1.0
  - [bb38d950](https://www.github.com/iotaledger/stronghold.rs/commit/bb38d950766552a70220b702cd014b8e15ba6ff2) update dependencies to local crates on 2022-10-18

## \[1.0.1]

- update to Stronghold 1.0
  - Bumped due to a bump in stronghold-runtime.
  - [f5a0cfdf](https://www.github.com/iotaledger/stronghold.rs/commit/f5a0cfdfc7c9a127cf92256b7782bbcae3d406b6) update bindings to Stronghold 1.0 on 2022-10-18
  - [a47c3cf3](https://www.github.com/iotaledger/stronghold.rs/commit/a47c3cf3c64d8aa6ee307e3b68069c259d5ea427) fix changes file on 2022-10-18

## \[1.0.0]

- Add a method to access the store of a Stronghold instance
  - [c14b04b6](https://www.github.com/iotaledger/stronghold.rs/commit/c14b04b646d7500722a8e1cabe9a3ba795fad821) Add change file on 2022-10-05
- Multithreaded stronghold with RwLock
  - [24c0d762](https://www.github.com/iotaledger/stronghold.rs/commit/24c0d7626af8ca925da9aec3fc7a782c06124339) Concurrency with locks ([#441](https://www.github.com/iotaledger/stronghold.rs/pull/441)) on 2022-10-13
- Remove p2p dependency
  - [6a4acd58](https://www.github.com/iotaledger/stronghold.rs/commit/6a4acd581fae415dd42bead887cb98c1213e9847) fix tests; remove dispatch mapper protoype on 2022-09-28
- Add a REPL as an interactive example application
  - [865b3e69](https://www.github.com/iotaledger/stronghold.rs/commit/865b3e69700febc30943b07398784e68553609bd) doc: add changes doc on 2022-10-17
- - Upgrade to crypto.rs 0.15.1
- Downgrade Zeroize to 1.3.0
- [be680479](https://www.github.com/iotaledger/stronghold.rs/commit/be68047942788c047c1ac8a9ef12776a974fee0a) dep: upgrade crypto.rs to latest version; downgrade zeroize on 2022-10-18

## \[0.9.1]

- upgrade dev-dependency for criterion
  - [f41e5dd7](https://www.github.com/iotaledger/stronghold.rs/commit/f41e5dd7b56bba30cf5e25ed9475cddef6f8b8e3) version: bump dev dependency of criterion to 0.4.0 on 2022-09-13

## \[0.9.0]

- bump dependency on crypto.rs to latest version
  - [5aee6c28](https://www.github.com/iotaledger/stronghold.rs/commit/5aee6c283a92eeee9f738b421f3c24f9e726ca7f) dep: upgrade dependency on crypto.rs on 2022-09-09
  - [1dc143d0](https://www.github.com/iotaledger/stronghold.rs/commit/1dc143d0e0373bd43ad21cf76985c0e1ca4989fd) feat: remove stronghold-native from version updates on 2022-09-09
- Add ConcatSecret as procedure to concatenate secrets from different locations together
  - [ce3a69d0](https://www.github.com/iotaledger/stronghold.rs/commit/ce3a69d0db6245c7dd5b4ec28adc2dbfb1279d37) feat: add ConcatSecret as procedure on 2022-07-25
- Store key to snapshot files in snapshot datastructure as an alternative to write and read Snapshots at a later time.
  Replace generic Key type with KeyProvider
  - [ea53e27c](https://www.github.com/iotaledger/stronghold.rs/commit/ea53e27cc8ba7dcda9bc17ddb997f6cb92c949b9) file: renamed on 2022-09-07

## \[0.8.1]

- Bip39 mnemonic will now be cleared before the procedure will be dropped
  - [36e60937](https://www.github.com/iotaledger/stronghold.rs/commit/36e60937ce7eb801d9b6b542384ffaa5cecaea7b) doc: add changes doc on 2022-07-14
  - [01cc3aab](https://www.github.com/iotaledger/stronghold.rs/commit/01cc3aab7f8bdd0d1754bbd5f5d5d03084316dfc) doc: fix to patch on 2022-07-14

## \[0.8.0]

- add insecure feature gated procedure to check values stored inside vault
  - [a30fc8ea](https://www.github.com/iotaledger/stronghold.rs/commit/a30fc8eace0ab6af92a44c8848ee848162db9652) doc: add changes doc on 2022-07-06
  - [aeb13540](https://www.github.com/iotaledger/stronghold.rs/commit/aeb1354034111335b67244de3e5eaf0af5a595df) doc: fix typo on 2022-07-06

## \[0.7.1]

- reduce visibility of Client runners `get_guard` function
  - [13b7ebb8](https://www.github.com/iotaledger/stronghold.rs/commit/13b7ebb877634aadfbb8f4610b44660141ab43ed) doc: add changes doc on 2022-07-05

## \[0.7.0]

- add clear() function to Stronghold, Client and Snapshot
  - [b71f75ed](https://www.github.com/iotaledger/stronghold.rs/commit/b71f75edff3f95722633a5e29b83b11fd3f6827a) fix: add changes file on 2022-07-04
  - [8c2f9ebb](https://www.github.com/iotaledger/stronghold.rs/commit/8c2f9ebb09fadffe75e3c35b93f49c5012d09648) fix: changes file on 2022-07-04

## \[0.6.4]

- iota-stronghold bumped utils dependency
  - [d350acfd](https://www.github.com/iotaledger/stronghold.rs/commit/d350acfd17dcee55f4aaa2ce0ccaa2e84ed1bd34) fix: bump stronghold patch version on 2022-06-27
  - [2d08c650](https://www.github.com/iotaledger/stronghold.rs/commit/2d08c6506b63b11f45cec356284cde66bfe33ae3) fix: module name on 2022-06-27
  - [0ddd0d4a](https://www.github.com/iotaledger/stronghold.rs/commit/0ddd0d4a77a225859c9de8ca1128eed43383e344) apply version updates on 2022-06-27
  - [92db69ea](https://www.github.com/iotaledger/stronghold.rs/commit/92db69eaffaec1dca1468d2900904152785d2ed5) fix: bump dependency on utils to 0.4.1 on 2022-06-27

## \[0.6.3]

- bump patch version
  - [d350acfd](https://www.github.com/iotaledger/stronghold.rs/commit/d350acfd17dcee55f4aaa2ce0ccaa2e84ed1bd34) fix: bump stronghold patch version on 2022-06-27
  - [2d08c650](https://www.github.com/iotaledger/stronghold.rs/commit/2d08c6506b63b11f45cec356284cde66bfe33ae3) fix: module name on 2022-06-27

## \[0.6.2]

- split random byte string into fixed and variable sized
  - Bumped due to a bump in stronghold-utils.
  - [34af5797](https://www.github.com/iotaledger/stronghold.rs/commit/34af5797df675912d9a78ea6a673b8a535ce1f91) Fix/remove riker from utils ([#252](https://www.github.com/iotaledger/stronghold.rs/pull/252)) on 2021-08-27
  - [3816aef5](https://www.github.com/iotaledger/stronghold.rs/commit/3816aef5111684ffbdbd12ed7f93b887e43e7a02) chore(release-doc): clean up outdated release notes, merge existing into one on 2022-05-31
  - [cc655878](https://www.github.com/iotaledger/stronghold.rs/commit/cc6558782928162f70614f6274a2ec87bd1a68d0) fix: utils version on 2022-06-27

## \[0.6.1]

- Loading a snapshot file will now return a new `ClientError` variant `SnapshotFileMissing`, if the snapshot file is not present
  Committing `Client` state into a snapshotfile will now check if all paths to the snapshot file are correct and will create the snapshot file, if it doesn't exist.
  - [2dddda13](https://www.github.com/iotaledger/stronghold.rs/commit/2dddda1310b1676ee36b20adebd09e9607417923) fix: refactored naming of 'SnapshotfileMissing' to 'SnapshotFileMissing' on 2022-06-24

## \[0.6.0]

- - update to crypto.rs `0.12.1`
- update to hkdf `0.12`
- [a340c6e2](https://www.github.com/iotaledger/stronghold.rs/commit/a340c6e23ef81ca5c3581e48ee81eccc76c214e9) add changes file on 2022-06-17
- Inserting a value into the `Store` will return an optional previous value
  - [1455038c](https://www.github.com/iotaledger/stronghold.rs/commit/1455038cc0a250df4d69fc36615826a0ba1b58b4) feat: add changes doc on 2022-06-17

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
