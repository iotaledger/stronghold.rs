---
"iota-stronghold": patch
"stronghold-engine" : patch

---

Upgraded snapshot format to age-encryption.org/v1 with password-based recipient stanza. This resolves the issue with the previous snapshot format encryption being insecure if used with weak passwords. Snapshot encryption doesn't use associated data.
Added sensitive data zeroization which would otherwise leak in stack and heap memory in plaintext after use.
`KeyProvider` unsafe constructors `with_passphrase_truncated`, `with_passphrase_hashed_argon2` were removed, `with_passphrase_hashed` constructor should be used instead.
Added snapshot encryption work factor public access. It should only be used in tests to decrease snapshot encryption/decryption times. It must not be used in production as low values of work factor might lead to secrets/seeds leakage.
Secp256k1 ECDSA + SLIP-10 support added.
Bump `iota-crypto` version to 0.22.1.
