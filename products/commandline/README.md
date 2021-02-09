# A Stronghold commandline interface

To show off the features of this set of libraries, an MVP command line tool was
created. This CLI is bare bones and based heavily off of the vault fuzz client.
Its main purpose is to show off the libraries in a minimal yet meaningful
manner. The structure of this application follows a kind of server/client
pattern.  The state of the database is maintained in a hashmap wrapped in a
RwLock and an Arc which is globally available via a lazy static macro. On the
frontend, there is a client which contains the client ID and a Vault structure.
The Vault structure contains the client’s key and a data view so that it can
interact with the data. The key implements a provider which inherits from the
box provider trait and this is where the encryption algorithm is defined. The
client and the backend are connected through a simple connection structure with
some basic logic to access the state hashmap.

Unlike the original vault fuzz client, this application needs to upload and
offload its data to and from a snapshot. To achieve this, a snapshot structure
was made; it consists of the client’s id and key as well as the database’s
hashmap. Each time a user runs this CLI they must submit a password to unlock
the snapshot so that the state can be loaded into the application. The id and
key are used to create a new client and a garbage collection operation is
executed to recreate the data chain from the incoming data. This operation
creates a new Initial Transaction and it iterates through each of the
transactions to verify that they are owned by the owner.  Any foreign data is
discarded in this process.

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
signifying that the operation succeeded. The record path must be a number. 
```shell
> stronghold encrypt --pass foo --plain secret --record_path 0
Ok(())
```
(Note that if you haven't/don't want to install the executable you can still
run this as: `cargo run -- encrypt --pass foo --plain secret --record_path 0`.)

To write insecure data to the stronghold's cache, use the write command.  Again, the record path must be a number. 
```shell
> stronghold write --pass foo --record_path 0 --plain test data
Ok(())
```

To read from the stronghold's cache, use the read command:
```shell
> stronghold read --pass foo --record_path 0
Ok(())
Data: "test"
```

Note that the vault and the cache are two separate databases so you can reuse record_paths. 

In order to make the following examples less trivial, we create another entry:
```shell
> stronghold encrypt --pass foo --plain secret --record_path 0
Ok(())
```
And now we can list the two records we currently have stored:
```shell
> stronghold list --pass foo
Ok(())
[(0, c29tZSBoaW50AAAAAAAAAAAAAAAAAAAA), (1, c29tZSBoaW50AAAAAAAAAAAAAAAAAAAA)]
```

When we grow tired of keeping the record we can `revoke` it:
```shell
> stronghold revoke --pass foo --record_path 0
Ok(())
```
And running the `list` command again we see that it has disappeared:
```shell
> stronghold list --pass foo
[(1, c29tZSBoaW50AAAAAAAAAAAAAAAAAAAA)]
```
But! The record is not actually removed until a garbage collection of the
chain has taken place.

So let's make sure it's actually removed:
```shell
> stronghold garbage_collect --pass foo
Ok(())
[(1, c29tZSBoaW50AAAAAAAAAAAAAAAAAAAA)]
```

## Usage
```
Engine POC CLI 1.0
Tensor Programming <tensordeveloper@gmail.com>
Encrypts data into the Engine Vault.  Creates snapshots and can load from snapshots.

USAGE:
    stronghold.exe [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    encrypt            Encrypt data to the vault. Writes to the snapshot.
    garbage_collect    Garbage collect the vault and remove revoked records.
    help               Prints this message or the help of the given subcommand(s)
    list               Lists the ids of the records inside of your stronghold's vault; lists the
                       record path and the hint hash.
    purge              Revoke a record by id and perform a gargbage collect
    read               Read the data from a record in the unencrypted store.
    revoke             Revoke a record from the vault.
    snapshot           load from an existing snapshot by path.
    take_ownership     Take ownership of an existing chain to give it to a new user.
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
Lists the ids of the records inside of your stronghold's vault; lists the record path and the hint hash.

USAGE:
    stronghold.exe list --pass <password>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -w, --pass <password>    the password for the snapshot.
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
Revoke a record by id and perform a gargbage collect

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

### take_ownership
```
Take ownership of an existing chain to give it to a new user.

USAGE:
    stronghold.exe take_ownership --pass <password>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -w, --pass <password>    the password for the snapshot.
```

