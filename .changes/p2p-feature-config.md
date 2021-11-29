---
"stronghold-p2p": patch
"iota-stronghold": patch
---

[[PR 276](https://github.com/iotaledger/stronghold.rs/pull/276)]
- Remove `relay` and `mdns` features.
- In the `StrongholdP2p` Interface enable / disable mdns and relay functionality on init via config flags in the `StrongholdP2pBuilder`.
  Per default, both are enabled.
- In the `Stronghold` client interface enable / disable mdns and relay in the `NetworkConfig` when spawning a new p2p-network actor.
  Per default, both are disabled.
