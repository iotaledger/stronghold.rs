# Stronghold Usage Examples

A few examples to explain how Stronghold works. Two types will be presented here: a simple command line interface for generating secrets, working with the store etc.
and showcasing the p2p functionality to exchange / execute remote cryptographic procedures over the p2p interface from Stronghold.

## Command Line Interface

All example should be run from withing the client crate.

### Generate an Ed25519 key pair and print the public key on console

Inside a shell run:

```lang:rust
$ cargo run --example cli generate-key --key-type Ed25519 --vault-path "vault_path" --record-path "record_path"
```

Executing this command should print something similar:

```
[2022-03-18T20:03:27Z INFO  cli] Generating keys with type ED25519
[2022-03-18T20:03:27Z INFO  cli] Using output location: vault_path=vault_path, record_path=record_path
[2022-03-18T20:03:27Z INFO  cli] Key generation successful? true
[2022-03-18T20:03:27Z INFO  cli] Creating public key
[2022-03-18T20:03:27Z INFO  cli] Public key is "9IYNQfZJQiHpQJZiHpYG2p6FEy8B9qGcwZ3Le8u1bU0=" (Base64)
```

### Write some value into the store, read it again and print the output on console

Inside a shell run:

```lang:rust
$ cargo run --example cli store-read-write  --key "key" --value "value"
```

This should give you following output:

```
[2022-03-18T20:08:31Z INFO  cli] Insert value into store "value" with key "key"
[2022-03-18T20:08:31Z INFO  cli] Store containts key "key" ? true
[2022-03-18T20:08:31Z INFO  cli] Value for key "key" ? "value"
```
