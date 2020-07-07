mod provider;
mod vault;

use snapshot::{decrypt_snapshot, encrypt_snapshot, snapshot_dir};

use clap::{load_yaml, App};

use std::fs::OpenOptions;

#[macro_export]
macro_rules! error_line {
    () => {
        concat!("Error at ", file!(), ":", line!())
    };
    ($str:expr) => {
        concat!($str, " @", file!(), ":", line!())
    };
}

fn main() {
    let yaml = load_yaml!("cli.yml");
    let matches = App::from(yaml).get_matches();

    if matches.subcommand_matches("encrypt").is_none()
        || matches.subcommand_matches("snapshot").is_none()
    {
        println!("Pass in --help to see how to use this commandline");
    }

    if let Some(matches) = matches.subcommand_matches("encrypt") {
        if let Some(ref _pass) = matches.value_of("password") {
            if let Some(ref plain) = matches.value_of("plain") {};
        };
    }
}
