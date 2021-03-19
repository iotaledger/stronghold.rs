# Changelog

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
