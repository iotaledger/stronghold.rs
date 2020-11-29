---
"client": major
"vault": minor
---

Added the initial client logic and integrated it with the Riker actor model. Change includes a Client/Cache actor, a Bucket actor, a Snapshot actor, and a keystore actor.  All of the Stronghold APIs are available. 

**Stronghold Requests**: 
- `CreateVault`: Creates a new vault which contains records.
- `InitRecord`: Initializes a new Record in the specified Vault. Based on the index of the vault (0-n).
- `ListIds`: Returns the `RecordIds` and `RecordHints` from the records contained in the specified Vault based on its index (0-n). 
- `WriteSnapshot`:  Writes a snapshot with a given password and path. If no path is given, the path will default to the `$HOME/.engine/snapshot` folder. The name of the snapshot defaults to `backup.snapshot`.
- `ReadSnapshot`:   Reads the snapshot with a given password and path. If no path is given, the path will default to the `$HOME/.engine/snapshot` folder. The name of the snapshot defaults to `backup.snapshot`.
- `WriteData`: Writes data into the head record in the specified Vault.  This action must be called after `CreateVault` or `InitRecord` must be called first or else this command will replace the data in the head record. 
- `ReadData` - Reads data from the head record of the specified Vault based on the index (0 - n).  Can only read from the head of the vault/chain.
- `RevokeData` - Marks a record for a deletion based on the specified vault. Can only target the head of the vault/chain.
- `GarbageCollect` - Cleans up any marked deletions and removes them from the the given vault. 

**Stronghold Responses**:
- `ReturnCreate`: Returns the index of the created vault from the `CreateVault` message. 
- `ReturnInit`: Returns the index of the Vault where a record was created using `InitRecord`. 
- `ReturnRead`: Returns the payload as a `Vec<u8>` of utf8 bytes as a result of the `ReadData` message.
- `ReturnList`: Returns a `Vec<(RecordId, RecordHint)>` containing all of the `RecordId`s and `RecordHint`s from the message `ListIds`.

To call the APIs, currently you must call `init_stronghold()` which will return a tuple of the Riker `ActorSystem` and a `ChannelRef` of type `SHResults`.  The `ActorSystem` is used to attach any external actors and the `ChannelRef` is used to collect the outgoing messages from stronghold. 

**TODOS**:
- Synchronization via 4th actor and status type.
- Add supervisors
- Add documentation
- Encrypted Return Channel
- Build a Handshake Process
- Create O(1) comparison for all IDS.
- Remove #[allow(dead_code)]s tags.
- Add more test coverage
- ~~Add ability to name snapshots~~
- Add ability to read and revoke records not on the head of the chain.
- Add Reference types for the RecordIds and VaultIds to expose to the External programs.