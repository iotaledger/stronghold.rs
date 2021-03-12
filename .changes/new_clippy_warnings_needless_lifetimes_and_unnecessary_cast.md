---
"runtime": patch
"vault": patch
---

Address two new clippy warnings: `needless_lifetimes` (addressed in the vault)
and `unnecessary_cast` (ignored in the runtime since they are necessary for
portability: `0 as libc::c_char` is not necessarily the same as `0_u8`).
