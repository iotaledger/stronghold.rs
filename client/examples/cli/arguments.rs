use clap::{Clap, Subcommand};

#[derive(Clap, Debug)]
#[clap(
    name = "Stronghold Example CLI",
    about = "Encrypts data into the Engine Vault.  Creates snapshots and can load from snapshots."
)]
pub struct Commands {
    #[clap(subcommand)]
    pub cmds: SubCommands,

    #[clap(default_value = "actor_path")]
    pub actor_path: String,
}

#[derive(Debug, Subcommand)]
pub enum SubCommands {
    #[clap(about = "Write data to the unencrypted cache store")]
    Write {
        #[clap(long, short = 'p', required = true, about = "the value you want to store.")]
        plain: String,

        #[clap(long, short = 'r', required = true)]
        record_path: String,

        #[clap(
            long,
            short = 'w',
            required = true,
            about = "the password you want to use to encrypt/decrypt the snapshot."
        )]
        pass: String,
    },
    #[clap(about = "Encrypt data to the vault. Writes to the snapshot.")]
    Encrypt {
        #[clap(long, short = 'p', required = true)]
        plain: String,

        #[clap(long, short = 'r', required = true)]
        record_path: String,

        #[clap(
            long,
            short = 'w',
            required = true,
            about = "the password you want to use to encrypt/decrypt the snapshot."
        )]
        pass: String,
    },
    #[clap(about = "Load from an existing snapshot by path.")]
    Snapshot {
        #[clap(long, short = 'p', required = true)]
        path: String,

        #[clap(
            long,
            short = 'w',
            required = true,
            about = "the password for the snapshot you want to load."
        )]
        pass: String,
    },
    #[clap(
        about = "Lists the ids of the records inside of your stronghold's vault; lists the record path and the hint hash."
    )]
    List {
        #[clap(long, short = 'w', required = true, about = "the password for the snapshot.")]
        pass: String,

        #[clap(long, short = 'r', required = true)]
        record_path: String,
    },
    #[clap(about = "Read the data from a record in the unencrypted store.")]
    Read {
        #[clap(long, short = 'w', required = true, about = "The password for the snapshot.")]
        pass: String,

        #[clap(long, short = 'r', required = true)]
        record_path: String,
    },
    #[clap(about = "Deletes from insecure store.")]
    Delete {
        #[clap(long, short = 'w', required = true)]
        pass: String,

        #[clap(long, short = 'p', required = true)]
        record_path: String,
    },
    #[clap(about = "Revoke a record from the vault.")]
    Revoke {
        #[clap(long = "pass", short = 'w', required = true, about = "The password for the snapshot")]
        password: String,

        #[clap(long = "record_path", short = 'i', required = true, about = "The id of the entry")]
        id: String,
    },

    #[clap(
        alias = "garbage_collect",
        about = "Garbage collect the vault and remove revoked records."
    )]
    GarbageCollect {
        #[clap(long, short = 'w', required = true, about = "The password for the snapshot.")]
        pass: String,

        #[clap(long, short = 'i', required = true, about = "The id of the entry")]
        id: String,
    },
    #[clap(about = "Revoke a record by id and perform a gargbage collect.")]
    Purge {
        #[clap(long = "id", short = 'i', required = true, about = "The id of the entry")]
        id: String,

        #[clap(
            long = "pass",
            short = 'w',
            required = true,
            about = "The password for the snapshot."
        )]
        password: String,
    },

    #[clap(
        alias = "take_ownership",
        about = "Take ownership of an existing chain to give it to a new user."
    )]
    TakeOwnership {
        #[clap(long = "pass", short = 'w', required = true, about = "The password for the snapshot")]
        password: String,
    },

    #[cfg(feature = "communication")]
    #[clap(alias = "relay", about = "Relay traffic to a peer.")]
    Relay {
        #[clap(long, short = 'p', required = true)]
        path: String,

        #[clap(long, short = 'i', required = true)]
        id: String,
    },
    #[cfg(feature = "communication")]
    #[clap(alias = "peers", about = "Lists all peers.")]
    Peers {},
}
