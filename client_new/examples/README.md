# Stronghold Usage Examples

A few examples to explain how Stronghold works. Two types will be presented here: a simple command line interface for generating secrets, working with the store etc.
and showcasing the p2p functionality to exchange / execute remote cryptographic procedures over the p2p interface from Stronghold.

## Command Line Interface

You should run the examples from within the [client crate](https://github.com/iotaledger/stronghold.rs/tree/dev/client). The examples shown in this doc were executed on Linux but should work on the other supported platforms. Make sure to adapt paths according to your operating system default. For example, Windows(TM) requires backslashes `\` as a delimiter for a path. This could pose a problem, as backslashes are also used to escape characters.

### TOC

- [Generate an Ed25519 key pair and print the public key on console](#generate-an-ed25519-key-pair-and-print-the-public-key-on-console)
- [Write some value into the store, read it again and print the output on console](#write-some-value-into-the-store-read-it-again-and-print-the-output-on-console)
- [Generate A BIP39 Seed and Return the Mnemonic Phrase](#generate-a-bip39-seed-and-return-the-mnemonic-phrase)
- [Generate SLIP10 Master Key](#generate-slip10-master-key)
- [Derive SLIP10 Private Public Keypair](#derive-slip10-private-public-keypair)
- [Create a snapshot](#create-a-snapshot)
- [Read a Snapshot From Filesystem](#read-a-snapshot-from-filesystem)
- [Recover a BIP39 Seed with a Mnemonic and Optional Passphrase](#recover-a-bip39-seed-with-a-mnemonic-and-optional-passphrase)

---

<a name="Generate-an-Ed25519-key-pair-and-print-the-public-key-on-console"></a>
## Generate an Ed25519 key pair and print the public key on console

This example will generate a Ed25519 key pair inside an ephemeral vault print the public key into the console.

```lang:rust
$ cargo run --example cli generate-key --key-type Ed25519 --vault-path "vault_path" --record-path "record_path"
```

Executing this command should print something similar:

```
[2022-03-28T08:21:47Z INFO  cli] Generating keys with type ED25519
[2022-03-28T08:21:47Z INFO  cli] Using output location: vault_path=vault_path, record_path=record_path
[2022-03-28T08:21:47Z INFO  cli] Key generation successful? true
[2022-03-28T08:21:47Z INFO  cli] Creating public key
[2022-03-28T08:21:47Z INFO  cli] Public key is "9IYNQfZJQiHpQJZiHpYG2p6FEy8B9qGcwZ3Le8u1bU0=" (Base64)
```

---

## Write some value into the store, read it again and print the output on console

A new ephemeral store is being created and a `value` with an associated `key` will be written into it.

```lang:rust
$ cargo run --example cli store-read-write  --key "key" --value "value"
```

This should give you following output:

```
[2022-03-28T08:21:47Z INFO  cli] Insert value into store "value" with key "key"
[2022-03-28T08:21:47Z INFO  cli] Store contains key "key" ? true
[2022-03-28T08:21:47Z INFO  cli] Value for key "key" ? "value"
```

## Generate A BIP39 Seed and Return the Mnemonic Phrase

This will create a new [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) seed with the associates mnemonic in the available languages. 
An optional passphrase can be provided to protect the seed.

```lang:rust
$ cargo run --example cli bip39-generate  --passphrase "optional-passphrase" --lang "japanese" --vault-path "vault-path-0" --record-path "record-path-0"
```

This should give you following output:
```
[2022-03-28T08:21:47Z INFO  cli] BIP39 Mnemonic: ほんしつ　あんぜん　ざんしょ　ひなまつり　りんご　けわしい　のみもの　ろしゅつ　へらす　せんさい　すずしい　ひんこん　あぶら　けんり　かいつう　しごと　きもの　ほんやく　くたびれる　むらさき　かいてん　たすける　あめりか　るいさい
```

## Generate SLIP10 Master Key

Derives a [SLIP10](https://github.com/satoshilabs/slips/blob/master/slip-0010.md) master key with optional size.

```lang:rust
$ cargo run --example cli slip10-generate --size 512 --vault-path "slip10-vault-path" --record-path "slip10-record-path"
```

This should give you following output:
```
[2022-03-28T08:24:00Z INFO  cli] SLIP10 seed successfully created? true
```


## Derive SLIP10 Private Public Keypair

This example creates an ephemeral SLIP10 master key and derives a private/public key pair from it. The public key will be returned.

```lang:rust
$ cargo run --example cli slip10-derive  --chain "/1234567/1234567" --input-vault-path "input-vault-path" --input-record-path "input-record-path" --output-vault-path "output-vault-path" --output-record-path "output-record-path"
```

This should give you following output:
```
[2022-03-28T08:24:38Z INFO  cli] Deriving SLIP10 Child Secret
[2022-03-28T08:24:38Z INFO  cli] Derivation Sucessful? true
```

## Create a Snapshot

This example creates a new snapshot on the file system and generates and stores a new key (Ed25519) inside the desired location.

```lang:rust
$ cargo run --example cli create-snapshot --path "/path/to/snapshot.file" --client-path "client-path-0" --vault-path "vault-path" --record-path "record-path" --key "passphrase"
```

This should give you following output:
```
[2022-03-28T08:27:35Z INFO  cli] Snapshot created successully true
```

## Read a Snapshot From Filesystem

This example reads a snapshot from the file system and returns the public key from the stored secret key (Ed25519) stored at the given location

```lang:rust
$ cargo run --example cli read-snapshot --path "/path/to/snapshot.file" --client-path "client-path-0" --vault-path "vault-path" --record-path "record-path" --key "passphrase"
```

This should give you following output:
```
[2022-03-28T08:29:33Z INFO  cli] Loading snapshot
[2022-03-28T08:29:33Z INFO  cli] Creating public key
[2022-03-28T08:29:33Z INFO  cli] Public key is "smsmXBG/Ln/Yjip72OJns4PB4iejVBIzs4MOXO9IkTE=" (Base64)
```

## Recover a BIP39 Seed with a Mnemonic and Optional Passphrase

This recovers a BIP39 seed with provided mnemonic and optional passphrase. The recovered seed will be stored at provided location. 

```lang:rust
$ cargo run --example cli bip39-recover --path "/path/to/snapshot.file" --client-path "client-path-0" --key "passphrase-for-snapshot" --mnemonic "けさき　にんか　せっさたくま　よかん　たいまつばな　ちんもく　そだてる　ふっこく　せっさたくま　しゃおん　そがい　つうはん　まなぶ　りくぐん　さのう" --passphrase "mnemonic-passphrase-if-present" --vault-path "vault-path" --record-path "record-path"
```

This should give you following output:
```
[2022-03-28T08:35:13Z INFO  cli] Loading snapshot
[2022-03-28T08:35:13Z INFO  cli] Recovering BIP39
[2022-03-28T08:35:13Z INFO  cli] BIP39 Recovery successful? true
```
