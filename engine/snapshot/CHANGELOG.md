# Changelog

## \[0.3.1]

- Updated cargo.toml files with the updated crypto.rs revisions and authors.
  Fixed logic in snapshot and providers to use the `try_*` encryption and decryption functions.
  Fixed commandline and stopped it from overwriting snapshots.
  - [64e08fe](https://www.github.com/iotaledger/stronghold.rs/commit/64e08fe39454d2191561783d009b155c91db37c1) add .changes. on 2021-03-19
  - [0758b67](https://www.github.com/iotaledger/stronghold.rs/commit/0758b6734a1e22d491345a6b894acea12ab5b1b7) add .changes. on 2021-03-19

## \[0.3.0]

- Add documentation and cleanup the code for these crates and modules in preparation for beta.
  - [dae0457](https://www.github.com/iotaledger/stronghold.rs/commit/dae04579cb20ad69a7aecdf102fb66ecac4aaf46) Beta Cleanup ([#166](https://www.github.com/iotaledger/stronghold.rs/pull/166)) on 2021-03-19
- Refactor the communication actor, enable using a relay peer, and integrate communication as feature into the stronghold interface.
  Remove unecessary Option/ Result wraps in `random` and `iota-stronghold`.
  Rename stronghold-test-utils to stronghold-utils and added riker ask pattern to it.
  - [9c7cba6](https://www.github.com/iotaledger/stronghold.rs/commit/9c7cba624e2a99f04a2d033b8673f8a4b8735f0b) Feat/integrate comms ([#130](https://www.github.com/iotaledger/stronghold.rs/pull/130)) on 2021-02-26
  - [fcb62bb](https://www.github.com/iotaledger/stronghold.rs/commit/fcb62bbf966bfcd543b13a79d73839a3fee0219e) fix/covector-2 ([#163](https://www.github.com/iotaledger/stronghold.rs/pull/163)) on 2021-03-12
- Blake2b hashing revision to use new upstream digest approach.
  - [04cc457](https://www.github.com/iotaledger/stronghold.rs/commit/04cc457497fc594a4453c86e23c999731efcb174) fix(snapshot): blake2b ([#153](https://www.github.com/iotaledger/stronghold.rs/pull/153)) on 2021-02-25
- Change the snapshot format to use an ephemeral X25519 private key and a key
  exchange with the users snapshot key to generate the key used in the XChaCha20
  cipher. This in order to mitigate offline attacks in the scenario that the
  cipher is compromised in such a way to reveal the key.
  - [6fca456](https://www.github.com/iotaledger/stronghold.rs/commit/6fca456a80993a99f38949f1cd3137a4a265a2e6) Use X25519 in the snapshot format ([#123](https://www.github.com/iotaledger/stronghold.rs/pull/123)) on 2021-02-08

## \[0.2.0]

- Alpha release of Stronghold: "Saint-Malo"
  - [4b6f4af](https://www.github.com/iotaledger/stronghold.rs/commit/4b6f4af29f6c21044f5063ec4a8d8aff643f81a7) chore(release) ([#105](https://www.github.com/iotaledger/stronghold.rs/pull/105)) on 2020-12-24
  - [06c6d51](https://www.github.com/iotaledger/stronghold.rs/commit/06c6d513dfcd1ba8ed6379177790ec6db28a6fea) fix(changelog): Alpha Release ([#106](https://www.github.com/iotaledger/stronghold.rs/pull/106)) on 2020-12-24
