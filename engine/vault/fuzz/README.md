## Vault Fuzz Client

### Description

This Fuzz client randomly calls actions on the Vault crate. A specified number of clients is defined and the fuzzer creates a number of owner ids based on that amount. A single key is created for the entire vault across all clients to simplify things. Clients are then generated with the key and one of the ids. Along with these clients, two global data structures maintain the data across the fuzzer.

Each of the clients can perform one of three actions determined by a random number generator (RNG): it can create a record, revoke a record or perform a garbage collection. There is a natural bias towards creating and revoking records so that these actions will happen more often. After one of these actions is completed, a `*` symbol is printed out. When the client reaches its verification number it will print out a `$` symbol.

A worker runs in the background and it reads the global storage into a `DBView`. This worker checks to see that the counters for each of the transactions are not moving out of order and then it sleeps for a second before performing this action again. After a successful loop, the worker prints out a `|` symbol.

A machine will also run in the background and this machine has the ability to assimilate a chain by taking ownership of it. The choice of which chain the machine will take ownership of is determined by a random number generator. Once assimilation occurs, a `^` symbol is printed out. The assimilation will only occur at the start of a verification event determined by a counter.

Verification happens when a specified number of transactions has occurred. The verification process involves reading data from a shadow storage and the global storage. The data from these two data structures is compared and should the two structures output different values the fuzzer will quit. Otherwise, the fuzzer will print out `##` and create a newline before starting the entire process again.

The fuzz client simulates a network through a simple connection interface. When a transaction is performed, it is sent to this connection interface and a random number generator determines if the transaction is successful. If the transaction fails this way, the client waits a specified amount of time before trying again.

### Execution instructions

A number of environment variables can be specified to tweak the behavior of the fuzz client. A user can specify a client count via the `CLIENT_COUNT` var. By default 30 clients are used by the system.

The error probability of the network can be set through the `ERROR_RATE` var. This determines how often transactions will fail and by default this value is set to 5 which means that it has a 1 in 5 chance to fail.

A verification number can be set through the `VERIFY_NUMBER` var. This determines when the system should initiate a verification event. By default this value is set to 155 and 155 transactions will occur before a verification is performed.

The user can set a retry delay value via the `RETRY_DELAY` var. This number determines how long the system should wait in milliseconds before trying to perform a transaction again. By default this value is set to 52.

The fuzz client can be executed by running `cargo run` or by using the `dockerfile` in the root of the project. If docker is used, make sure to uncomment the `build vault fuzzer` line and comment out the `build crypto fuzzer line`.
