# A Stronghold commandline interface

To show off the features of this set of libraries, an MVP command line tool was created. 
Its main purpose is to show off the libraries in a minimal yet meaningful
manner.  The command line tool uses the client to interface with the vault and store.   
The Vault structure contains the client’s key and a data view so that it can
interact with the data. The key implements a provider which inherits from the
box provider trait and this is where the encryption algorithm is defined..

This application does not use a daemon therefore it must upload and offload its data 
to a snapshot after every command. To achieve this, a snapshot structure
was made; it consists of the client’s id and key as well as the state from the client. 
Each time a user runs this CLI they must submit a password to unlock
the snapshot so that the state can be loaded into the application. 

## Installation
Build and install using [cargo](https://doc.rust-lang.org/cargo/):
```shell
> cargo install --path .
```
By default this will install the `stronghold` executable under the user's cargo
directory: `~/.cargo/bin/stronghold`, so make sure it's in your `PATH`:
```shell
> export PATH=~/.cargo/bin:$PATH
```
and refer to your shell's manual to make the change permanent
([bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html#Bash-Startup-Files),
[zsh](http://zsh.sourceforge.net/Doc/Release/Files.html#Startup_002fShutdown-Files)).

If you only want to play around without installing anything you can run the
commmandline interface directly:
```shell
> cargo run -- --help
```
That is in the usage examples below replace `stronghold` with `cargo run --`
(note however that by default the snapshots will still be saved under the
`~/.engine` directory).

## Examples
By default, `stronghold` will store its snapshots under the `~/.engine`
directory. The location can be overridden by setting the `STRONGHOLD`
environment variable.

Create a new chain by encrypting some data and get back the status result; with `Ok(())` 
signifying that the operation succeeded. The record path can be a string or a number. 
```shell
> stronghold encrypt --pass foo --plain secret --record_path "some path"
Ok(())
```
(Note that if you haven't/don't want to install the executable you can still
run this as: `cargo run -- encrypt --pass foo --plain secret --record_path "some path"`.)

To write insecure data to the stronghold's cache, use the write command.  Again, the record path can be a number or a string. 
```shell
> stronghold write --pass foo --record_path "some path" --plain test
Ok(())
```

To read from the stronghold's cache, use the read command:
```shell
> stronghold read --pass foo --record_path "some path"
Ok(())
Data: "test"
```

Note that the vault and the cache are two separate databases so you can reuse record_paths. 

In order to make the following examples less trivial, we create another entry:
```shell
> stronghold encrypt --pass foo --plain secret --record_path "some other path"
Ok(())
```
And now we can use the list command to see the record stored on this path:
```shell
> stronghold list --pass foo --record_path "some other path"
Ok(())
[(2, c29tZSBoaW50AAAAAAAAAAAAAAAAAAAA)]
```

When we grow tired of keeping the record we can `revoke` it:
```shell
> stronghold revoke --pass foo --record_path "some other path"
Ok(())
```
And running the `list` command again we see that it has disappeared:
```shell
> stronghold list --pass foo --record_path "some other path"
[]
```
But! The record is not actually removed until a garbage collection of the
chain has taken place.

So let's make sure it's actually removed:
```shell
> stronghold garbage_collect --pass foo --record_path "some other path"
Ok(())
[]
```

## Usage
```
Stronghold CLI 2.0
IOTA Stiftung, Tensor Programming <tensordeveloper@gmail.com>
Encrypts data into the Engine Vault.  Creates snapshots and can load from snapshots.

USAGE:
    stronghold.exe [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    encrypt            Encrypt data to the vault. Writes to the snapshot.
    garbage_collect    Garbage collect the vault and remove revoked records by record id.
    help               Prints this message or the help of the given subcommand(s)
    list               Lists the ids of the records inside of your stronghold's vault by
                       inputted record id.
    purge              Revoke a record by id and perform a gargbage collect on the record id
    read               Read the data from a record in the unencrypted store.
    revoke             Revoke a record from the vault.
    snapshot           load from an existing snapshot by path.
    write              Write data to the unencrypted cache store.
```

### encrypt
```
Encrypt data to the vault. Writes to the snapshot.

USAGE:
    stronghold.exe encrypt --plain <plaintext> --record_path <Record Path value> --pass <password>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -w, --pass <password>
            the password you want to use to encrypt/decrypt the snapshot.

    -p, --plain <plaintext>                  a plaintext value that you want to encrypt.
    -r, --record_path <Record Path value>
```

### write
```
Write data to the unencrypted cache store.

USAGE:
    stronghold.exe write --plain <plaintext> --record_path <Record Path value> --pass <password>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -w, --pass <password>
            the password you want to use to encrypt/decrypt the snapshot.

    -p, --plain <plaintext>                  a value you want to store.
    -r, --record_path <Record Path value>
```

### read
```
Read the data from a record in the unencrypted store.

USAGE:
    stronghold.exe read --pass <password> --record_path <Record Path value>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -w, --pass <password>                    the password for the snapshot.
    -r, --record_path <Record Path value>
```

### list
```
Lists the ids of the records inside of your stronghold's vault by inputted record id.

USAGE:
    stronghold.exe list --pass <password> --record_path <Record Path value>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -w, --pass <password>                    the password for the snapshot.
    -r, --record_path <Record Path value>
```

### revoke
```
Revoke a record from the vault.

USAGE:
    stronghold.exe revoke --pass <password> --record_path <id>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -w, --pass <password>     the password for the snapshot.
    -r, --record_path <id>    the id of the entry
```

### purge
```
Revoke a record by id and perform a gargbage collect on the record id

USAGE:
    stronghold.exe purge --pass <password> --id <id>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -i, --id <id>            the id of the entry
    -w, --pass <password>    the password for the snapshot.
```

### snapshot
```
load from an existing snapshot by path.

USAGE:
    stronghold.exe snapshot --path <snapshot path> --pass <password>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -w, --pass <password>         the password for the snapshot you want to load.
    -p, --path <snapshot path>
```