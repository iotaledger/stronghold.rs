---
"stronghold-engine": patch
---

Added snapshot encryption work factor public access. It should only be used in tests to decrease snapshot encryption/decryption times. It must not be used in production as low values of work factor might lead to secrets/seeds leakage.
