# Changelog

## \[2.0.0-rc.1]

- [`f9619747`](https://www.github.com/iotaledger/stronghold.rs/commit/f96197471cb894e1a5a08caa4e9393703e5b8d1b)([#489](https://www.github.com/iotaledger/stronghold.rs/pull/489)) Added support for Secp256k1 ECDSA with SHA256/Keccak256 variants.
  Bump `iota-crypto` version to 0.22.1.

### Dependencies

- Upgraded to `stronghold-runtime@2.0.0-rc.1`

## \[2.0.0-rc.0]

- [`12ce12fe`](https://www.github.com/iotaledger/stronghold.rs/commit/12ce12fe3d28456eabacce6e608e81c3b4e0ec20) Secp256k1 ECDSA + SLIP-10 support added.
  Bump `iota-crypto` version to 0.21.2.
- [`1e72f00f`](https://www.github.com/iotaledger/stronghold.rs/commit/1e72f00fe8e188082e55b39c46986d928817e2dd)([#474](https://www.github.com/iotaledger/stronghold.rs/pull/474)) Upgraded snapshot format to age-encryption.org/v1 with password-based recipient stanza. This resolves the issue with the previous snapshot format encryption being insecure if used with weak passwords. Snapshot encryption doesn't use associated data.
  Added sensitive data zeroization which would otherwise leak in stack and heap memory in plaintext after use.
  `KeyProvider` unsafe constructors `with_passphrase_truncated`, `with_passphrase_hashed_argon2` were removed, `with_passphrase_hashed` constructor should be used instead.
- [`988a9d1f`](https://www.github.com/iotaledger/stronghold.rs/commit/988a9d1fda6f8f652e014712b4cfff3737e0fb54)([#477](https://www.github.com/iotaledger/stronghold.rs/pull/477)) Added snapshot encryption work factor public access. It should only be used in tests to decrease snapshot encryption/decryption times. It must not be used in production as low values of work factor might lead to secrets/seeds leakage.

## \[1.1.0]

- Bump `iota-crypto` version to 0.18.0. `Pbkdf2Hmac::count` changed to a `NonZeroU32`.
  - [a860896c](https://www.github.com/iotaledger/stronghold.rs/commit/a860896c56a3ebae2bef9ffb37e3effff074fa79) Bump crypto on 2023-05-03
  - [03ff2dcd](https://www.github.com/iotaledger/stronghold.rs/commit/03ff2dcd59326b923d319b7ee33224091db838b6) better changelog on 2023-05-03
  - [74e564d2](https://www.github.com/iotaledger/stronghold.rs/commit/74e564d2d76624e267d85c02ac3a6eca1bc1af32) even more betterer changelog on 2023-05-03
  - [6d32ae45](https://www.github.com/iotaledger/stronghold.rs/commit/6d32ae4549c02989b6d68b15f8536bb8374c40a4) remove native on 2023-05-03

## \[1.0.2]

- Disable frag module for android and ios targets.
  - [0a2331a9](https://www.github.com/iotaledger/stronghold.rs/commit/0a2331a906493c3466f029155601aa0cda8f363d) Fix clippy and add covector changefile on 2022-11-14
  - [21fbdc68](https://www.github.com/iotaledger/stronghold.rs/commit/21fbdc68dbee1e803be1ed214e0e1f98ebffe711) Add changefiles on 2022-11-15
  - [4561e4a9](https://www.github.com/iotaledger/stronghold.rs/commit/4561e4a93e2c7119e5da04c1eb5b505303bb3114) Merge changefiles on 2022-11-15

## \[1.0.1]

- update version of zeroize
  - [5eba6e8c](https://www.github.com/iotaledger/stronghold.rs/commit/5eba6e8cc77caeb30e1259c90518a03226212877) update zeroize on 2022-10-19

## \[1.0.0]

- update to Stronghold 1.0
  - [f5a0cfdf](https://www.github.com/iotaledger/stronghold.rs/commit/f5a0cfdfc7c9a127cf92256b7782bbcae3d406b6) update bindings to Stronghold 1.0 on 2022-10-18
  - [a47c3cf3](https://www.github.com/iotaledger/stronghold.rs/commit/a47c3cf3c64d8aa6ee307e3b68069c259d5ea427) fix changes file on 2022-10-18

## \[0.5.6]

- - Upgrade to crypto.rs 0.15.1
- Downgrade Zeroize to 1.3.0
- Bumped due to a bump in stronghold-runtime.
- [be680479](https://www.github.com/iotaledger/stronghold.rs/commit/be68047942788c047c1ac8a9ef12776a974fee0a) dep: upgrade crypto.rs to latest version; downgrade zeroize on 2022-10-18

## \[0.5.5]

- upgrade dev-dependency for criterion
  - [f41e5dd7](https://www.github.com/iotaledger/stronghold.rs/commit/f41e5dd7b56bba30cf5e25ed9475cddef6f8b8e3) version: bump dev dependency of criterion to 0.4.0 on 2022-09-13

## \[0.5.4]

- bump dependency on crypto.rs to latest version
  - [5aee6c28](https://www.github.com/iotaledger/stronghold.rs/commit/5aee6c283a92eeee9f738b421f3c24f9e726ca7f) dep: upgrade dependency on crypto.rs on 2022-09-09
  - [1dc143d0](https://www.github.com/iotaledger/stronghold.rs/commit/1dc143d0e0373bd43ad21cf76985c0e1ca4989fd) feat: remove stronghold-native from version updates on 2022-09-09

## \[0.5.3]

- split random byte string into fixed and variable sized
  - Bumped due to a bump in stronghold-utils.
  - [34af5797](https://www.github.com/iotaledger/stronghold.rs/commit/34af5797df675912d9a78ea6a673b8a535ce1f91) Fix/remove riker from utils ([#252](https://www.github.com/iotaledger/stronghold.rs/pull/252)) on 2021-08-27
  - [3816aef5](https://www.github.com/iotaledger/stronghold.rs/commit/3816aef5111684ffbdbd12ed7f93b887e43e7a02) chore(release-doc): clean up outdated release notes, merge existing into one on 2022-05-31
  - [cc655878](https://www.github.com/iotaledger/stronghold.rs/commit/cc6558782928162f70614f6274a2ec87bd1a68d0) fix: utils version on 2022-06-27

## \[0.5.2]

- bump all crate versions to update to new utils modules
  - [29ad7932](https://www.github.com/iotaledger/stronghold.rs/commit/29ad7932550ec558915ec88c7f26408dd2c763e7) version: bump all crates to include updated utils on 2022-06-03
  - [699117f7](https://www.github.com/iotaledger/stronghold.rs/commit/699117f7ea834c043596418f8ff2c502c477bf6b) version: bump all crates to include updated utils on 2022-06-03
  - [34ada641](https://www.github.com/iotaledger/stronghold.rs/commit/34ada641a6ac987e9c17d8d71581a5083bd61911) fix: covector fixx crate name on 2022-06-03
  - [092ce898](https://www.github.com/iotaledger/stronghold.rs/commit/092ce898a31440e4d5740f40952fbf711da8ce02) fix: covector fixx crate name on 2022-06-03
  - [f01e99e3](https://www.github.com/iotaledger/stronghold.rs/commit/f01e99e319f286f2b094ee9efe88cf44a638fa45) version: reset to former versions on 2022-06-03
  - [b441e6f4](https://www.github.com/iotaledger/stronghold.rs/commit/b441e6f476571f067cdddd93c9ae8370d59733ba) fix: versions on 2022-06-03

## \[0.5.2]

- bump all crate versions to update to new utils crate
  - [29ad7932](https://www.github.com/iotaledger/stronghold.rs/commit/29ad7932550ec558915ec88c7f26408dd2c763e7) version: bump all crates to include updated utils on 2022-06-03
  - [699117f7](https://www.github.com/iotaledger/stronghold.rs/commit/699117f7ea834c043596418f8ff2c502c477bf6b) version: bump all crates to include updated utils on 2022-06-03
  - [34ada641](https://www.github.com/iotaledger/stronghold.rs/commit/34ada641a6ac987e9c17d8d71581a5083bd61911) fix: covector fixx crate name on 2022-06-03
  - [092ce898](https://www.github.com/iotaledger/stronghold.rs/commit/092ce898a31440e4d5740f40952fbf711da8ce02) fix: covector fixx crate name on 2022-06-03

## \[0.5.2]

- bump version
  - Bumped due to a bump in stronghold-utils.
  - [8548949b](https://www.github.com/iotaledger/stronghold.rs/commit/8548949b691ed85ec9140f28fc7eff11126916b3) version: bump utils on 2022-06-02
  - [96d895ae](https://www.github.com/iotaledger/stronghold.rs/commit/96d895aea09504d146176dd5b878e6144a01f1ae) apply version updates on 2022-06-02
  - [f5e8a7a8](https://www.github.com/iotaledger/stronghold.rs/commit/f5e8a7a80fc9e7b16a8974f2905fe1cfb4d645f2) version: fix utils version; enable bump on 2022-06-02
  - [c3757950](https://www.github.com/iotaledger/stronghold.rs/commit/c3757950fc1cd3b16167512584bfe89c5c50ffa6) apply version updates on 2022-06-02
  - [a6524545](https://www.github.com/iotaledger/stronghold.rs/commit/a6524545088fbf02ac013e47a80c0bf3e987c481) version: reset all versions; bump utils on 2022-06-02

## \[0.5.3]

- bump version
  - Bumped due to a bump in stronghold-utils.
  - [8548949b](https://www.github.com/iotaledger/stronghold.rs/commit/8548949b691ed85ec9140f28fc7eff11126916b3) version: bump utils on 2022-06-02
  - [96d895ae](https://www.github.com/iotaledger/stronghold.rs/commit/96d895aea09504d146176dd5b878e6144a01f1ae) apply version updates on 2022-06-02
  - [f5e8a7a8](https://www.github.com/iotaledger/stronghold.rs/commit/f5e8a7a80fc9e7b16a8974f2905fe1cfb4d645f2) version: fix utils version; enable bump on 2022-06-02

## \[0.5.2]

- bump
  - Bumped due to a bump in stronghold-utils.
  - [8548949b](https://www.github.com/iotaledger/stronghold.rs/commit/8548949b691ed85ec9140f28fc7eff11126916b3) version: bump utils on 2022-06-02

## \[0.5.1]

- Bump
  - Bumped due to a bump in stronghold-runtime.
  - [6f1c160a](https://www.github.com/iotaledger/stronghold.rs/commit/6f1c160a3182f136868406bdca99022efd45dd67) Fix versions for covector on 2022-06-01

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

## \[0.4.0]

- Merged Store, Vault and Snapshot into a single crate called Stronghold-Engine.
  Merged utils-derive and communication-macros into a new crate called stronghold-derive
  Export Stronghold-derive through Stronghold-utils.
  - [36c8983](https://www.github.com/iotaledger/stronghold.rs/commit/36c8983eefd594c702a9e8b32bad25354ad127c0) merge derive/macro crates. on 2021-04-21
  - [b7d44f5](https://www.github.com/iotaledger/stronghold.rs/commit/b7d44f530e08be27128f25f46b4bb05cf3da99bd) update config. on 2021-04-21

## \[0.3.1]

- Updated cargo.toml files with the updated crypto.rs revisions and authors.
  Fixed logic in snapshot and providers to use the `try_*` encryption and decryption functions.
  Fixed commandline and stopped it from overwriting snapshots.
  - Bumped due to a bump in snapshot.
  - [64e08fe](https://www.github.com/iotaledger/stronghold.rs/commit/64e08fe39454d2191561783d009b155c91db37c1) add .changes. on 2021-03-19
  - [0758b67](https://www.github.com/iotaledger/stronghold.rs/commit/0758b6734a1e22d491345a6b894acea12ab5b1b7) add .changes. on 2021-03-19
- Remove old logic from client and vault.
  Added clear cache logic and message to stop the client actor.
  Removed Client Derive Data hashmap.
  - [81892aa](https://www.github.com/iotaledger/stronghold.rs/commit/81892aa704b920c50de2517e8073943d8bf0c2b9) add md file. on 2021-04-20
- move stronghold-utils and add utils-derive for proc macros.
  rebuild vault and remove versioning.
  update client to use new vault.
  - [5490f0a](https://www.github.com/iotaledger/stronghold.rs/commit/5490f0aaaf58e5322a5569c02669514ec067b02f) refactor vault ([#181](https://www.github.com/iotaledger/stronghold.rs/pull/181)) on 2021-04-15

## \[0.3.0]

- Added zeroing allocator to the runtime.\
  Placed zeroing allocator in the vualt.
  - Bumped due to a bump in vault.
  - [a960e50](https://www.github.com/iotaledger/stronghold.rs/commit/a960e50a591e82e74df12093513a136594a5f8e6) add changes. on 2021-03-12
- Add documentation and cleanup the code for these crates and modules in preparation for beta.
  - Bumped due to a bump in vault.
  - [dae0457](https://www.github.com/iotaledger/stronghold.rs/commit/dae04579cb20ad69a7aecdf102fb66ecac4aaf46) Beta Cleanup ([#166](https://www.github.com/iotaledger/stronghold.rs/pull/166)) on 2021-03-19
- Refactor the communication actor, enable using a relay peer, and integrate communication as feature into the stronghold interface.
  Remove unecessary Option/ Result wraps in `random` and `iota-stronghold`.
  Rename stronghold-test-utils to stronghold-utils and added riker ask pattern to it.
  - Bumped due to a bump in vault.
  - [9c7cba6](https://www.github.com/iotaledger/stronghold.rs/commit/9c7cba624e2a99f04a2d033b8673f8a4b8735f0b) Feat/integrate comms ([#130](https://www.github.com/iotaledger/stronghold.rs/pull/130)) on 2021-02-26
  - [fcb62bb](https://www.github.com/iotaledger/stronghold.rs/commit/fcb62bbf966bfcd543b13a79d73839a3fee0219e) fix/covector-2 ([#163](https://www.github.com/iotaledger/stronghold.rs/pull/163)) on 2021-03-12
- Address two new clippy warnings: `needless_lifetimes` (addressed in the vault)
  and `unnecessary_cast` (ignored in the runtime since they are necessary for
  portability: `0 as libc::c_char` is not necessarily the same as `0_u8`).
  - Bumped due to a bump in vault.
  - [1614243](https://www.github.com/iotaledger/stronghold.rs/commit/161424322af84bd4626aac5a3f96b0c529d7b39a) Add a changelog message on 2021-01-04
  - [42ed9d6](https://www.github.com/iotaledger/stronghold.rs/commit/42ed9d6b5fe93f7cf7ecb1b9591bd10de9c35e58) fix(covector) ([#162](https://www.github.com/iotaledger/stronghold.rs/pull/162)) on 2021-03-12
- Remove Crypto, Random and Primitives libraries in favor of Crypto.rs
  Moved Runtime into the engine.
  Add new guarded types for Runtime and remove old logic.
- Add documentation and cleanup the code for these crates and modules in preparation for beta.
  - [dae0457](https://www.github.com/iotaledger/stronghold.rs/commit/dae04579cb20ad69a7aecdf102fb66ecac4aaf46) Beta Cleanup ([#166](https://www.github.com/iotaledger/stronghold.rs/pull/166)) on 2021-03-19
- Create key:value store for insecure data storage and retrieval.
  - [0ba3398](https://www.github.com/iotaledger/stronghold.rs/commit/0ba3398987dcbb168e210bc4b2b6e295e5a020c6) chore(covector): add store config & changelog on 2021-01-05
- Blake2b hashing revision to use new upstream digest approach.
  - [04cc457](https://www.github.com/iotaledger/stronghold.rs/commit/04cc457497fc594a4453c86e23c999731efcb174) fix(snapshot): blake2b ([#153](https://www.github.com/iotaledger/stronghold.rs/pull/153)) on 2021-02-25
- Change the snapshot format to use an ephemeral X25519 private key and a key
  exchange with the users snapshot key to generate the key used in the XChaCha20
  cipher. This in order to mitigate offline attacks in the scenario that the
  cipher is compromised in such a way to reveal the key.
  - [6fca456](https://www.github.com/iotaledger/stronghold.rs/commit/6fca456a80993a99f38949f1cd3137a4a265a2e6) Use X25519 in the snapshot format ([#123](https://www.github.com/iotaledger/stronghold.rs/pull/123)) on 2021-02-08

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

- Bumped due to a bump in vault.
- [dd65b67](https://www.github.com/iotaledger/stronghold.rs/commit/dd65b67f42718150c7c7dbab9606ee2167cf11ce) add changes. on 2021-03-11
- [829ecac](https://www.github.com/iotaledger/stronghold.rs/commit/829ecac2e8090d478706c673cd45f1b91a60b2de) fix(covector) ([#164](https://www.github.com/iotaledger/stronghold.rs/pull/164)) on 2021-03-12

## \[0.2.0]

- Alpha release of Stronghold: "Saint-Malo"
  - [4b6f4af](https://www.github.com/iotaledger/stronghold.rs/commit/4b6f4af29f6c21044f5063ec4a8d8aff643f81a7) chore(release) ([#105](https://www.github.com/iotaledger/stronghold.rs/pull/105)) on 2020-12-24
  - [06c6d51](https://www.github.com/iotaledger/stronghold.rs/commit/06c6d513dfcd1ba8ed6379177790ec6db28a6fea) fix(changelog): Alpha Release ([#106](https://www.github.com/iotaledger/stronghold.rs/pull/106)) on 2020-12-24
- Added the initial client logic and integrated it with the Riker actor model. Change includes a Client/Cache actor, a Bucket actor, a Snapshot actor, and a keystore actor.  All of the Stronghold APIs are available.
  - [7c7320a](https://www.github.com/iotaledger/stronghold.rs/commit/7c7320ab0bc71749510a590f418c9bd70329dc02) add client changelog. on 2020-11-30
  - [4986685](https://www.github.com/iotaledger/stronghold.rs/commit/49866854f32dde8589f37c6d9ea0c2e7ddb3c461) remove todos and update readme. on 2020-11-30
  - [7f1e9ed](https://www.github.com/iotaledger/stronghold.rs/commit/7f1e9edf5f5c5e148376575057a55d1d1398708a) Chore/covector fix ([#61](https://www.github.com/iotaledger/stronghold.rs/pull/61)) on 2020-12-01
  - [f882754](https://www.github.com/iotaledger/stronghold.rs/commit/f88275451e7d3c140bbfd1c90a9267aa222fb6d0) fix(client): readme and changelog ([#64](https://www.github.com/iotaledger/stronghold.rs/pull/64)) on 2020-12-01
- Alpha release of Stronghold: "Saint-Malo"
  - [4b6f4af](https://www.github.com/iotaledger/stronghold.rs/commit/4b6f4af29f6c21044f5063ec4a8d8aff643f81a7) chore(release) ([#105](https://www.github.com/iotaledger/stronghold.rs/pull/105)) on 2020-12-24
  - [06c6d51](https://www.github.com/iotaledger/stronghold.rs/commit/06c6d513dfcd1ba8ed6379177790ec6db28a6fea) fix(changelog): Alpha Release ([#106](https://www.github.com/iotaledger/stronghold.rs/pull/106)) on 2020-12-24
