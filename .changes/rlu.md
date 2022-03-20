---
"stronghold-rlu": minor
---

- asynchronuous software transactional memory framework as replacement for actix actor system
- integration is runtime agnostic an can be used by any async runtime for rust, tkio is encouraged though
- memory operations can be secured by a feature flagged build of this crate. Use `guardmem` to enable guared memory with build-in encryption. 
