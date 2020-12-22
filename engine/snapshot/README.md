# Snapshot

This crate defines and implements the encrypted offline storage format used by
the Stronghold ecosystem.

The format has a header with version and magic bytes to appease applications
wishing to provide media-type (MIME) detection of the snapshot artifact.

The data stored within a snapshot is considered opaque and uses 256 bit keys.
It provides recommended ways to derive the snapshot encryption key from a user
provided password. The format also allows using an authenticated data
bytestring to further protect the offline snapshot files (one might consider
using a secondary user password strengthened by an HSM).

The current version of the format is using the symmetric XChaCha20 cipher with
the Poly1305 message authentication algorithm.

Future versions will consider using X25519 to encrypt using an ephemeral key
instead of directly using the user's key. When the demands for larger
snapshot sizes and/or random access is desired, one might consider encrypting
smaller chunks (B-trees?) or similar using derived ephemeral keys.
