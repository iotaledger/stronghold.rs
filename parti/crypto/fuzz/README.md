## Vault Fuzz Client

### Description

This Fuzz Client sends random data into the cryptographic algorithms defined in the crypto crate to verify their integrity against their `libsodium` counterparts. ChaCha20Poly1305 and XChaCha20Poly1305 are used because they test all of the other encryption algorithms in the crate indirectly. Random data is sent into the algorithms and compared to `libsodium`. If the data is different from the expected data on `libsodium` the fuzzer fails and prints out the metadata regarding that specific input.

### Execution instructions

The user can set a two environment variables for this client. A `NUM_THREADS` var can be set to specify how many thread should be used. By default, the client will use all of the threads on the system. A `VECTOR_LIMIT` var can be set to specify how large the random inputted encrypted data can be. By default, this value is set to 264 bytes.

The fuzz client can be executed by running `cargo run` or by using the `dockerfile` in the root of the project. If docker is used, make sure to uncomment the `build crypto fuzzer line` line and comment out the `build vault fuzzer` line.
