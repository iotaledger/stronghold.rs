---

"iota-stronghold": minor
"stronghold-engine" : minor
"stronghold-runtime" : minor
"vault" : minor
"snapshot" : minor

---

Upgraded snapshot format to age-encryption.org/v1 with password-based recipient stanza. This resolves the issue with the previous snapshot format encryption being insecure if used with weak passwords. Snapshot encryption doesn't use associated data.
Added sensitive data zeroization which would otherwise leak in stack and heap memory in plaintext after use.
`KeyProvider` unsafe constructors `with_passphrase_truncated`, `with_passphrase_hashed_argon2` were removed, `with_passphrase_hashed` constructor should be used instead.
