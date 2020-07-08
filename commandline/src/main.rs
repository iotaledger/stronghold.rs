mod client;
mod connection;
mod crypt;
mod provider;
mod state;

use clap::{load_yaml, App};

use std::fs::OpenOptions;

#[macro_export]
macro_rules! line_error {
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

    let read_old_snapshot = OpenOptions::new().read(true).open("../data.snapshot");

    if let Some(matches) = matches.subcommand_matches("encrypt") {
        if let Some(ref _pass) = matches.value_of("password") {
            if let Some(plain) = matches.value_of("plain") {
                if let Err(_) = read_old_snapshot {
                } else {
                }
            };
        };
    }
}
