---
"snapshot": minor
---

Change the snapshot format to use an ephemeral X25519 private key and a key
exchange with the users snapshot key to generate the key used in the XChaCha20
cipher. This in order to mitigate offline attacks in the scenario that the
cipher is compromised in such a way to reveal the key.
