---
"iota-stronghold": patch
"stronghold-p2p": patch
---

[[PR 290](https://github.com/iotaledger/stronghold.rs/pull/290)]
- Persist the state of stronghold-p2p in the `SecureClient` by serializing the `NetworkConfig` and writing it to the store.
- Allow loading stored states into the `NetworkActor` on init.
- Allow reuse of same `Keypair` that is stored in the vault.
