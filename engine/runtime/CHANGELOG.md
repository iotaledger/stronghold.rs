# Changelog

## \[2.0.0-rc.0]

- [`12ce12fe`](https://www.github.com/iotaledger/stronghold.rs/commit/12ce12fe3d28456eabacce6e608e81c3b4e0ec20) Secp256k1 ECDSA + SLIP-10 support added.
  Bump `iota-crypto` version to 0.21.2.
- [`1e72f00f`](https://www.github.com/iotaledger/stronghold.rs/commit/1e72f00fe8e188082e55b39c46986d928817e2dd)([#474](https://www.github.com/iotaledger/stronghold.rs/pull/474)) Upgraded snapshot format to age-encryption.org/v1 with password-based recipient stanza. This resolves the issue with the previous snapshot format encryption being insecure if used with weak passwords. Snapshot encryption doesn't use associated data.
  Added sensitive data zeroization which would otherwise leak in stack and heap memory in plaintext after use.
  `KeyProvider` unsafe constructors `with_passphrase_truncated`, `with_passphrase_hashed_argon2` were removed, `with_passphrase_hashed` constructor should be used instead.

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

## \[0.6.0]

- - Upgrade to crypto.rs 0.15.1
- Downgrade Zeroize to 1.3.0
- [be680479](https://www.github.com/iotaledger/stronghold.rs/commit/be68047942788c047c1ac8a9ef12776a974fee0a) dep: upgrade crypto.rs to latest version; downgrade zeroize on 2022-10-18

## \[0.5.4]

- upgrade dev-dependency for criterion
  - [f41e5dd7](https://www.github.com/iotaledger/stronghold.rs/commit/f41e5dd7b56bba30cf5e25ed9475cddef6f8b8e3) version: bump dev dependency of criterion to 0.4.0 on 2022-09-13

## \[0.5.3]

- bump dependency on crypto.rs to latest version
  - [5aee6c28](https://www.github.com/iotaledger/stronghold.rs/commit/5aee6c283a92eeee9f738b421f3c24f9e726ca7f) dep: upgrade dependency on crypto.rs on 2022-09-09
  - [1dc143d0](https://www.github.com/iotaledger/stronghold.rs/commit/1dc143d0e0373bd43ad21cf76985c0e1ca4989fd) feat: remove stronghold-native from version updates on 2022-09-09

## \[0.5.2]

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

## \[0.5.0]

- Bump
  - [6f1c160a](https://www.github.com/iotaledger/stronghold.rs/commit/6f1c160a3182f136868406bdca99022efd45dd67) Fix versions for covector on 2022-06-01

## \[0.2.0]

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
