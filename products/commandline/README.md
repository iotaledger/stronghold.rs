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

Create a new chain by encrypting some data and get back the unique identifier
of the newly created encrypted record containing our plain-text data:
```shell
> stronghold encrypt --pass foo --plain secret text
zCeX9poxiirzBpiJGVE7wDReo5sYgyeS
```
(Note that if you haven't/don't want to install the executable you can still
run this as: `cargo run -- encrypt --pass foo --plain "secret text"`.)

To read and decrypt the record we use the `read` command:
```shell
> stronghold read --pass foo --id zCeX9poxiirzBpiJGVE7wDReo5sYgyeS
Plain: "secret text"
```

In order to make the following examples less trivial, we create another entry:
```shell
> stronghold encrypt --pass foo --plain another secret is 42
GxOmjt1Y7fBdZEYPf56dz-CAKq8RGo-7
```
And now we can list the two records we currently have stored:
```shell
> stronghold list --pass foo
Id: zCeX9poxiirzBpiJGVE7wDReo5sYgyeS, Hint: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Id: GxOmjt1Y7fBdZEYPf56dz-CAKq8RGo-7, Hint: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

When we grow tired of keeping the record we can `revoke` it:
```shell
> stronghold revoke --pass foo --id zCeX9poxiirzBpiJGVE7wDReo5sYgyeS
```
And running the `list` command again we see that it has disappeared:
```shell
> stronghold list --pass foo
Id: GxOmjt1Y7fBdZEYPf56dz-CAKq8RGo-7, Hint: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```
But! The record is not actually removed until a garbage collection of the
chain has taken place.
Here's how you can see all records stored (not only the valid/unrevoked
records):
```shell
> stronghold list --pass foo --all
Id: zCeX9poxiirzBpiJGVE7wDReo5sYgyeS
Id: GxOmjt1Y7fBdZEYPf56dz-CAKq8RGo-7
```
So let's make sure it's actually removed:
```shell
> stronghold garbage_collect --pass foo
Id: GxOmjt1Y7fBdZEYPf56dz-CAKq8RGo-7, Hint: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```
And check that it has in fact been removed:
```shell
> stronghold list --pass foo --all
Id: GxOmjt1Y7fBdZEYPf56dz-CAKq8RGo-7
```
## Usage
```
Engine POC CLI 1.0
Tensor Programming <tensordeveloper@gmail.com>
Encrypts data into the Engine Vault.  Creates snapshots and can load from snapshots.
USAGE:
    stronghold [SUBCOMMAND]
FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information
SUBCOMMANDS:
    encrypt            
    garbage_collect    Garbage collect the entire vault and remove revoked records.
    help               Prints this message or the help of the given subcommand(s)
    list               Lists the ids of the records inside of your main snapshot
    purge              Revoke a record by id and perform a gargbage collect
    read               read an associated record by id
    revoke             Revoke a record by id
    snapshot           load from an existing snapshot
    take_ownership     Take ownership of an existing chain.
```

### encrypt
```
stronghold-encrypt 
USAGE:
    stronghold encrypt --plain <plaintext> --pass <password>
FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information
OPTIONS:
    -w, --pass <password>      the password you want to use to encrypt/decrypt the snapshot.
    -p, --plain <plaintext>    a plaintext value that you want to encrypt.
```

### read
```
stronghold-read 
read an associated record by id
USAGE:
    stronghold read --pass <password> --id <id>
FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information
OPTIONS:
    -i, --id <id>            the id of the record you want to read.
    -w, --pass <password>    the password for the snapshot.
```

### list
```
stronghold-list 
Lists the ids of the records inside of your main snapshot
USAGE:
    stronghold list [FLAGS] --pass <password>
FLAGS:
    -A, --all        include revoked records
    -h, --help       Prints help information
    -V, --version    Prints version information
OPTIONS:
    -w, --pass <password>    the password for the snapshot.
```

### revoke
```
stronghold-revoke 
Revoke a record by id
USAGE:
    stronghold revoke --pass <password> --id <id>
FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information
OPTIONS:
    -i, --id <id>            the id of the entry
    -w, --pass <password>    the password for the snapshot.
```