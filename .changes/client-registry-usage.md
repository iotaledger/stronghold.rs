---
"iota-stronghold": patch
---

[[PR 270](https://github.com/iotaledger/stronghold.rs/pull/270)]
- Move management of network-Actor and client-target into Registry
- Make client-target optional, in case that it is killed before switching to another target
- Make registry a normal actor instead of a system-service
