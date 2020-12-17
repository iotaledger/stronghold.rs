# Snapshot

This crate defines and implements the encrypted offline storage format used by
Stronghold ecosystem.

The format has a header with version and magic bytes to appease applications
wishing to provide file-type detection.

The data stored within a snapshot is considered opaque and can uses 256 bit keys.
It provides recommended ways to derive the snapshot encryption key from a user
provided password. The format also allows using an authenticated data
bytestring to further protect the offline snapshot files (one might consider
using a secondary user password strengthened by an HSM).

The current version of the format is using the symmetric XChaCha20 cipher with
the Poly1305 message authentication algorithm.

Future versions will consider using X25519 to encrypt using an ephemeral key
instead of directly using the users key. When the demands for larger
snapshot sizes and/or random access is desired one might consider encrypting
smaller chunks (B-trees?) or similar using derived ephemeral keys.
