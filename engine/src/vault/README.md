## Stronghold Vault
 
Vault is an implementation of a secure database for secrets. From an abstract point of view, each database view is a vault which is a collection of records which are all encrypted using the same key.  And a collection of vaults is called a Stronghold. 

The vault module defines a `Vault` type. Each of these vaults is composed of `Records`. Each `Record` is split into multiple pieces: an id, a data transaction, an optional revocation transaction and the blob of encrypted data. Internally, the data uses the `GuardedVec` type from the runtime module to guard the data for when it is accessed from the `DbView` interface. On the `DbView` interface there are methods for writing data, updating data and deleting data. To delete a record from a vault, a revocation transaction must be added to a record which marks it for garbage collection via the `revoke_record` method. The records may then be garbage collected using the `garbage_collect_vault` method. The `write` method can be used to both write to a new record or update existing records. 

The `get_guard` method allows the user to insert a closure which accepts the `GuardedVec` and returns a `engine::Result<()>`.  Through this closure, the user can interact with the `GuardedVec` to manipulate the data. The `exec_proc` method is a version of `get_guard` that accepts two vault locations, vault keys and also a closure of type `FnOnce(GuardedVec<u8>) -> crate::Result<Vec<u8>>`. This method places the result of the closure into the newly specified `Record` in the vault. 

