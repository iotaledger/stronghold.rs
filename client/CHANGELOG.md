# Changelog

## [0.2.0]

-   Added the initial client logic and integrated it with the Riker actor model. Change includes a Client/Cache actor, a Bucket actor, a Snapshot actor, and a keystore actor.  All of the Stronghold APIs are available.
    -   [7c7320a](https://www.github.com/iotaledger/stronghold.rs/commit/7c7320ab0bc71749510a590f418c9bd70329dc02) add client changelog. on 2020-11-30
    -   [4986685](https://www.github.com/iotaledger/stronghold.rs/commit/49866854f32dde8589f37c6d9ea0c2e7ddb3c461) remove todos and update readme. on 2020-11-30
    -   [7f1e9ed](https://www.github.com/iotaledger/stronghold.rs/commit/7f1e9edf5f5c5e148376575057a55d1d1398708a) Chore/covector fix ([#61](https://www.github.com/iotaledger/stronghold.rs/pull/61)) on 2020-12-01
    -   [f882754](https://www.github.com/iotaledger/stronghold.rs/commit/f88275451e7d3c140bbfd1c90a9267aa222fb6d0) fix(client): readme and changelog ([#64](https://www.github.com/iotaledger/stronghold.rs/pull/64)) on 2020-12-01
-   Create SignUnlockBlock procedure.
    -   [f9d180a](https://www.github.com/iotaledger/stronghold.rs/commit/f9d180a85fe57c2942d6ebabfcfdb3c445b0ba5b) feat(client): introduce SignUnlockBlock proc ([#92](https://www.github.com/iotaledger/stronghold.rs/pull/92)) on 2020-12-21
-   Alpha release of Stronghold: "Saint-Malo"
    -   [4b6f4af](https://www.github.com/iotaledger/stronghold.rs/commit/4b6f4af29f6c21044f5063ec4a8d8aff643f81a7) chore(release) ([#105](https://www.github.com/iotaledger/stronghold.rs/pull/105)) on 2020-12-24
    -   [06c6d51](https://www.github.com/iotaledger/stronghold.rs/commit/06c6d513dfcd1ba8ed6379177790ec6db28a6fea) fix(changelog): Alpha Release ([#106](https://www.github.com/iotaledger/stronghold.rs/pull/106)) on 2020-12-24
-   Introduce release manager for rust crates including tangle registry.
    -   [c10811e](https://www.github.com/iotaledger/stronghold.rs/commit/c10811effbff396370762e76a2f2d44221dc7327) feat(covector): rigging ([#57](https://www.github.com/iotaledger/stronghold.rs/pull/57)) on 2020-11-29
-   Add a hierarchical wallet implementation following SLIP10 for the Ed25519 curve.
    -   [dd12c16](https://www.github.com/iotaledger/stronghold.rs/commit/dd12c16d628ec996728d356cfb815f185cc5cc37) Add changelog message on 2020-12-02
    -   [d3c63be](https://www.github.com/iotaledger/stronghold.rs/commit/d3c63bec8052c0cd6a636fef3463b90893b55d4b) fix(covector) ([#82](https://www.github.com/iotaledger/stronghold.rs/pull/82)) on 2020-12-17
