---
"iota-stronghold": patch
---

[[PR 254](https://github.com/iotaledger/stronghold.rs/pull/254)]  
Change key handling in the `SecureClient` to avoid unnecessary cloning of `Key`s.
Remove obsolete VaultId-HashSet from the `SecureClient`.
