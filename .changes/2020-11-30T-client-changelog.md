---
"client": minor
"vault": patch
---

Added the initial client logic and integrated it with the Riker actor model. Change includes a Client/Cache actor, a Bucket actor, a Snapshot actor, and a keystore actor.  All of the Stronghold APIs are available. 

**Stronghold Requests**: 
- `CreateVault`: Creates a new vault which contains records.
- `InitRecord`: Initializes a new Record in the specified Vault.
- `ListIds`: Returns the `RecordIds` and `RecordHints` from the records contained in the specified Vault
- `WriteSnapshot`:  Writes a snapshot with a given password, filename and path. If no path is given, the path will default to the `$HOME/.engine/snapshot` folder. The name of the snapshot defaults to `backup.snapshot`.
- `ReadSnapshot`:   Reads the snapshot with a given password, filename and path. If no path is given, the path will default to the `$HOME/.engine/snapshot` folder. The name of the snapshot defaults to `backup.snapshot`.
- `WriteData`: Writes data into the record in the specified Vault. If a `RecordId` is not specified, it will write to the head of the vault. This action must be called after `CreateVault` or `InitRecord` must be called first or else this command will replace the data in the record. 
- `ReadData` - Reads data from the record of the specified Vault. If a `RecordId` is not specified, it will write to the head of the vault.  
- `RevokeData` - Marks a record for a deletion based on the specified vault. 
- `GarbageCollect` - Cleans up any marked deletions and removes them from the the given vault. 

**Stronghold Responses**:
- `ReturnCreate`: Returns the new `VaultId` and first `RecordId` from the `CreateVault` message. 
- `ReturnInit`: Returns the `VaultId` and the `RecordId` for the Record that was created using `InitRecord`. 
- `ReturnRead`: Returns the payload as a `Vec<u8>` of utf8 bytes as a result of the `ReadData` message.
- `ReturnList`: Returns a `Vec<(RecordId, RecordHint)>` containing all of the `RecordId`s and `RecordHint`s from the message `ListIds`.
- `ReturnRebuild` Returns the results of `ReadSnapshot`, a `Vec<VaultId>` containing newly generated `VaultId`s and a `Vec<Vec<RecordId>>` containing all of the records for each vault in order.

To call the APIs, currently you must call `init_stronghold()` which will return a tuple of the Riker `ActorSystem` and a `ChannelRef` of type `SHResults`.  The `ActorSystem` is used to attach any external actors and the `ChannelRef` is used to collect the outgoing messages from stronghold. 