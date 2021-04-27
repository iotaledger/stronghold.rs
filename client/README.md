## Stronghold Client

This is the official client layer of Stronghold. It provides a Riker actor model system for easy Interface as well as functional passthrough to Stronghold's internal actor system for integrators not using Riker. 

**Stronghold Interface**: 
- `init_stronghold_system`: Initializes a new instance of the Stronghold system.  Sets up the first client actor. Accepts a `ActorSystem`, the first `client_path`: `Vec<u8>` and any `StrongholdFlags` which pertain to the first actor.
- `spawn_stronghold_actor`:  Spawns a new set of actors for the Stronghold system. Accepts the `client_path`: `Vec<u8>` and the options: `StrongholdFlags`
- `switch_actor_target`: Switches the actor target to another actor in the system specified by the `client_path`: `Vec<u8>`.
- `write_to_vault`:  Writes data into the Stronghold. Uses the current target actor as the client and writes to the specified location of `Location` type. The payload must be specified as a `Vec<u8>` and a `RecordHint` can be provided. Also accepts `VaultFlags` for when a new Vault is created.
- `write_to_store`: Writes data into an insecure cache. This method, accepts a `Location`, a `Vec<u8>` and an optional `Duration`. The lifetime allows the data to be deleted after the specified duration has passed. If not lifetime is specified, the data will persist until it is manually deleted or over-written. Each store is mapped to a client. 
- `read_from_store`: Reads from an insecure cache. This method, accepts a `Location` and returns the payload in the
form of a `Vec<u8>`.  If the location does not exist, an empty vector will be returned along with an error `StatusMessage`.
- `delete_from_store` - delete data from an insecure cache. This method, accepts a `Location` and returns a `StatusMessage`.
- `delete_data`: Revokes the data from the specified location of type `Location`. Revoked data is not readable and can be removed from a vault with a call to `garbage_collect`.  if the `should_gc` flag is set to `true`, this call with automatically cleanup the revoke. Otherwise, the data is just marked as revoked. 
- `garbage_collect`: Garbage collects any revokes in a Vault based on the given vault_path and the current target actor.
- `list_hints_and_ids`: Returns a list of the available `RecordId` and `RecordHint` values in a vault by the given `vault_path`. 
- `runtime_exec`: Executes a runtime command given a `Procedure`.  Returns a `ProcResult` based off of the `control_request` specified.
- `record_exists`: Checks whether a record exists in the client based off of the given `Location`.
- `vault_exists`: Checks whether a vault exists in the client by `Location`.
- `read_snapshot`: Reads data from a given snapshot file. Can only read the data for a single `client_path` at a time. If the actor uses a new `client_path` the former client path may be passed into the function call to read the data into the new actor. A filename and filepath can be specified, if they aren't provided, the path defaults to `$HOME/.stronghold/snapshots/` and the filename defaults to `backup.stronghold`.
Also requires keydata to unlock the snapshot and the keydata must implement and use `Zeroize`.
- `write_all_to_snapshot`:  Writes the entire state of the `Stronghold` into a snapshot. All Actors and their associated data is written into the specified snapshot. Requires keydata to encrypt the snapshot. The Keydata should implement and use Zeroize.  If a path and filename are not provided, uses the default path `$HOME/.stronghold/snapshots/` and the default filename `backup.stronghold`.
- `kill_stronghold`: Used to kill a stronghold actor or clear the cache of that actor. Accepts the `client_path`, and a boolean for whether or not to kill the actor.  If `kill_actor` is `true` both the internal actor and the client actor are killed. Otherwise, the cache is cleared from the client and internal actor. 


**Stronghold Procedures**:

##### **Requests**: 
- `SLIP10Generate`: Generate a raw SLIP10 seed of the specified size (in bytes, defaults to 64 bytes/512 bits) and store it in the `Location`. 
- `SLIP10Derive`: Derive a Slip10 child key from a seed or parent key. Store the output in a specified `Location` and return the corresponding `ChainCode`. 
- `BIP39Recover`: Use a BIP39 mnemonic sentence (optionally protected by a passphrase) to create or recover a BIP39 seed and store it in the output `Location`.
- `BIP39Generate`: Generate a BIP39 seed and its corresponding mnemonic sentence (optionally protected by a passphrase) and store them in the output `Location`.
- `BIP39MnemonicSentence`: Read a BIP39 seed and its corresponding mnemonic sentence (optionally protected by a passphrase) and store them in the output `Location`.
- `Ed25519PublicKey`: Derive an Ed25519 public key from the corresponding private key stored at the specified `Location`.
- `Ed25519Sign`: Use the specified Ed25519 compatible key to sign the given message. Compatible keys are any record that contain the desired key material in the first 32 bytes, in particular SLIP10 keys are compatible.

##### **Responses**:
- `SLIP10Generate`: Returns a `StatusMessage` indicating the result of the request. 
- `SLIP10Derive`: Returns a `ResultMessage` with the `ChainCode` inside of it. 
- `BIP39Recover`: Returns a `StatusMessage` indicating the result of the request. .
- `BIP39Generate`: Returns a `StatusMessage` indicating the result of the request.
- `BIP39MnemonicSentence`: Returns the mnemonic sentence for the corresponding seed.
- `Ed25519PublicKey`: Returns an Ed25519 public key inside of a `ResultMessage`.
- `Ed25519Sign`: Returns an Ed25519 signature inside of a `ResultMessage`.