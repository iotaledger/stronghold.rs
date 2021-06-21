## Stronghold Vault

Vault is an in-memory database specification which is designed to work without a central server. Only the user which holds the associated id and key may modify the data in a vault. Another owner can take control over the data if they know the id and the key.

Data can be added to the chain via a [DataTransaction]. The [DataTransaction] is associated to the chain through the owner’s ID and it contains its own randomly generated ID.

Records may also be revoked from the Vault through a [RevocationTransaction]. A [RevocationTransaction] is created and it references the id of a existing [DataTransaction]. The RevocationTransaction stages the associated record for deletion. The record is deleted when the DbView preforms a garbage collection and the [RevocationTransaction] is deleted along with it.