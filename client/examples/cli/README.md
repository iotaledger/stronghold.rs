# Stronghold Command Line Example

Some basic operations on stronghold from the command line. With the example you 
can:

- write a secret to insecure store
- read a secret from insecure store
- encrypt a secret to secure vault and write it to a snapshot
- load an existing snapshot
- revoke secrets
- purge secrets

## Quickstart

Run this command to write a secret to the insecure store
```
cargo run --example cli write --w "password" --p "hello, world!" --r 0
```
