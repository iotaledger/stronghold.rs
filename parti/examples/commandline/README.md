# Commandline

To show off the features of this set of libraries, an MVP command line tool was created. This CLI is bare bones and based heavily off of the vault fuzz client. Its main purpose is to show off the libraries in a minimal yet meaningful manner. The structure of this application follows a kind of server/client pattern.  The state of the database is maintained in a hashmap wrapped in a RwLock and an Arc which is globally available via a lazy static macro. On the frontend, there is a client which contains the client ID and a Vault structure.  The Vault structure contains the client’s key and a data view so that it can interact with the data. The key implements a provider which inherits from the box provider trait and this is where the encryption algorithm is defined. The client and the backend are connected through a simple connection structure with some basic logic to access the state hashmap.

Unlike the original vault fuzz client, this application needs to upload and offload its data to and from a snapshot. To achieve this, a snapshot structure was made; it consists of the client’s id and key as well as the database’s hashmap. Each time a user runs this CLI they must submit a password to unlock the snapshot so that the state can be loaded into the application. The id and key are used to create a new client and a garbage collection operation is executed to recreate the data chain from the incoming data. This operation creates a new Initial Transaction and it iterates through each of the transactions to verify that they are owned by the owner.  Any foreign data is discarded in this process.

## Usage
```
cargo build
cd target/debug
./stronghold --help
```
