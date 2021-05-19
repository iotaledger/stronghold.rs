use clap::{Clap, Subcommand};

#[derive(Clap, Debug)]
#[clap(name = "cli")]
pub struct Commands {
    #[clap(subcommand)]
    pub cmds: SubCommands,
}

#[derive(Debug, Subcommand)]
pub enum SubCommands {
    Write {
        #[clap(long, short = 'p', required = true)]
        plain: String,

        #[clap(long, short = 'r', required = true)]
        record_path: String,

        #[clap(long, short = 'w', required = true)]
        pass: String,
    },
    Encrypt {
        #[clap(long, short = 'p', required = true)]
        plain: String,

        #[clap(long, short = 'r', required = true)]
        record_path: String,

        #[clap(long, short = 'w', required = true)]
        pass: String,
    },
    Snapshot {
        #[clap(long, short = 'p', required = true)]
        path: String,

        #[clap(long, short = 'w', required = true)]
        pass: String,
    },
    List {
        #[clap(long, short = 'w', required = true)]
        pass: String,

        #[clap(long, short = 'r', required = true)]
        record_path: String,
    },
    Read {
        #[clap(long, short = 'w', required = true)]
        pass: String,

        #[clap(long, short = 'r', required = true)]
        record_path: String,
    },
    Revoke {
        #[clap(long = "pass", short = 'w', required = true)]
        password: String,

        #[clap(long = "record_path", short = 'i', required = true)]
        id: String,
    },

    #[clap(alias = "garbage_collect")]
    GarbageCollect {
        #[clap(long, short = 'w', required = true)]
        pass: String,

        #[clap(long, short = 'i', required = true)]
        id: String,
    },
    Purge {
        #[clap(long = "id", short = 'i', required = true)]
        id: String,

        #[clap(long = "pass", short = 'w', required = true)]
        password: String,
    },

    #[clap(alias = "take_ownership")]
    TakeOwnership {
        #[clap(long = "pass", short = 'w', required = true)]
        password: String,
    },

    #[cfg(feature = "communication")]
    Relay {
        #[clap(long, short = 'p', required = true)]
        path: String,

        #[clap(long, short = 'i', required = true)]
        id: String,
    },
    Peers,
}
