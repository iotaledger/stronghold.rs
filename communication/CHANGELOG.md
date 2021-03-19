# Changelog

## \[0.3.0]

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

## \[0.2.0]

- Patch libp2p dependecy version from `v0.28` to `v0.33`
  - [bbd35b7](https://www.github.com/iotaledger/stronghold.rs/commit/bbd35b7fa813108a9a9afdd04f349b406d9fc81b) chore(communication): bump libp2p version ([#88](https://www.github.com/iotaledger/stronghold.rs/pull/88)) on 2020-12-18
- Refactor the communication actor by adding config and implementing a seperate struct for the swarm task.
  - [dfbcb15](https://www.github.com/iotaledger/stronghold.rs/commit/dfbcb15b04a12eb249638cbbe33cf572314ac0e0) fix(communication): add changelog on 2020-12-21
- Update the examples, add documentation, reimplement QueryError as BehaviourError.
  - [4b6f4af](https://www.github.com/iotaledger/stronghold.rs/commit/4b6f4af29f6c21044f5063ec4a8d8aff643f81a7) chore(release) ([#105](https://www.github.com/iotaledger/stronghold.rs/pull/105)) on 2020-12-24
- Alpha release of Stronghold: "Saint-Malo"
  - [4b6f4af](https://www.github.com/iotaledger/stronghold.rs/commit/4b6f4af29f6c21044f5063ec4a8d8aff643f81a7) chore(release) ([#105](https://www.github.com/iotaledger/stronghold.rs/pull/105)) on 2020-12-24
  - [06c6d51](https://www.github.com/iotaledger/stronghold.rs/commit/06c6d513dfcd1ba8ed6379177790ec6db28a6fea) fix(changelog): Alpha Release ([#106](https://www.github.com/iotaledger/stronghold.rs/pull/106)) on 2020-12-24
- Introduction of the libp2p communication subsystem for Stronghold.
  - [06d881e](https://www.github.com/iotaledger/stronghold.rs/commit/06d881efd4522efec6ca5d9c39aa51210a731391) feat(p2p): add changelog file on 2020-12-01
  - [c8da228](https://www.github.com/iotaledger/stronghold.rs/commit/c8da2285ecb163c34bef3be100e064d5024b5d33) fix(p2p): typo on 2020-12-01
