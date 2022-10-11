// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Read Evaluate Print Loop (REPL) Example fot Stronghold
//!
//! The REPL will accept commands in the following order
//! action {create, read, write, derive, recover} -> context {key, bip39, slip10, store}

mod error;
mod util;

use error::*;
use iota_stronghold::{SnapshotPath, Stronghold};
use std::fmt::Display;
use util::*;

pub const HELP_MESSAGE: &str = r#"
Stronghold REPL (Read Evaluate Print Loop). This demo program showcases the basic
usage of Stronghold. The REPL follows a sequence of two steps.

- enter a desire action (see below for a list of possible actions)
- enter a context to work with (see below for a list of possible contexts)

The REPL allows you to do stuff, that is normally non-sensical, but allowed eg.
you can create a snapshot file without any clients. This operation is permitted, 
but may not be useful.


Note: The REPL stores internally the state of a running Stronghold
instance, and must be initialized with the action "init". Follow the
instructions on the CLI.

Actions:
    - create
    - read
    - write
    - derive
    - recover
    - help
    - reset 
    - init
    - check

Contexts:
    - snapshot
    - key
    - bip39
    - slip10
    - store

"#;

#[derive(Debug, Clone)]
pub enum Context {
    /// Persistence context to store runtime secrets to disk
    /// note: requires additional parameter for setting the path to the snapshot file as well as the snapshot
    /// passphrase
    Snapshot(Snapshot),

    /// For all key related operations
    /// note: requires additional parameter for key type Ed25519, X25519
    Key(Key),

    /// Specialized bip39 mnemonic generation
    BIP39,

    /// Slip10 seed generation and derivation
    SLIP10,

    /// Storing non secret data
    Store(Store),

    /// unused context
    None,
}

#[derive(Debug, Clone)]
pub enum Action {
    Create,
    Read,
    Write,
    Derive,
    Recover,
    Help,
    Reset,
    Init,
    Check,
}

/// The [`Actionable`] trait shall be used on the [`Context`]
/// to run the desired [`Action`]
trait Actionable: Sized {
    type Error;

    /// This function shall be called to create something within a context
    fn create(&self) -> Result<(), Self::Error>;

    fn read(&self) -> Result<(), Self::Error>;

    fn write(&self) -> Result<(), Self::Error>;

    fn derive(&self) -> Result<(), Self::Error>;

    fn recover(&self) -> Result<(), Self::Error>;
}

impl TryFrom<String> for Action {
    type Error = ReplError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let lower = value.to_lowercase();
        let trimmed = lower.trim();

        match trimmed {
            "create" => Ok(Action::Create),
            "read" => Ok(Action::Read),
            "write" => Ok(Action::Write),
            "derive" => Ok(Action::Derive),
            "recover" => Ok(Action::Recover),
            "help" => Ok(Action::Help),
            "reset" => Ok(Action::Reset),
            "init" => Ok(Action::Init),
            "check" => Ok(Action::Check),
            _ => Err(ReplError::InvalidAction),
        }
    }
}

impl Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Display for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl TryFrom<String> for Context {
    type Error = ReplError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str().trim() {
            "snapshot" => Ok(Context::Snapshot(Snapshot { path: None })),
            "key" => Ok(Context::Key(Key::default())),
            "bip39" => Ok(Context::BIP39),
            "slip10" => Ok(Context::SLIP10),
            "store" => Ok(Context::Store(Store::default())),
            _ => Err(ReplError::InvalidContext),
        }
    }
}

impl Context {
    pub fn parse(&mut self) -> Result<(), ReplError> {
        match self {
            Context::Snapshot(inner) => {
                print_requirement("Enter the path the Stronghold snapshot file");
                let line = read_line()?;

                inner.path.replace(line);
            }
            Context::Key(key) => {
                print_requirement("Enter the key type to use. Possible values \"ed25519\", \"x25519\" ");
                let keytype: KeyType = read_line()?.try_into()?;

                key.keytype.replace(keytype);
            }
            Context::BIP39 => {}
            Context::SLIP10 => {}
            Context::Store(store) => {
                print_requirement("Enter the storage key");
                let store_key = read_line()?;

                // reading storage value may be optional, of reading from store has been selected
                print_requirement("Enter the storage value");
                let store_value = read_line()?;

                store.key.replace(store_key);
                store.value.replace(store_value);
            }
            Context::None => {}
        }

        Ok(())
    }
}

fn print_requirement<D>(requirement: D)
where
    D: Display,
{
    println(requirement);
    print("> ");
}

#[derive(Debug, Clone)]
pub enum KeyType {
    ED25519,
    X25519,
}

impl TryFrom<String> for KeyType {
    type Error = ReplError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let lower = value.to_lowercase();
        let trimmed = lower.trim();

        match trimmed {
            "ed25519" => Ok(KeyType::ED25519),
            "x25519" => Ok(KeyType::X25519),
            _ => Err(ReplError::UnknownValue),
        }
    }
}

// ---  BEGIN specific data types
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    path: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Key {
    keytype: Option<KeyType>,
}

#[derive(Debug, Clone, Default)]
pub struct Store {
    key: Option<String>,
    value: Option<String>,
}

// --- END specific data types

#[derive(Default, Clone)]
struct Repl {
    state: Option<Stronghold>,
    action: Option<Action>,
    ctx: Option<Context>,
    client_path: Option<String>,
}

impl Repl {
    pub fn run(&mut self) -> Result<(), ReplError> {
        draw_caret();
        match self.parse_action()? {
            Action::Init => {
                print_requirement("Enter client path to use");
                self.parse_client_path()?;
                self.init()?;

                return Ok(());
            }
            Action::Help => {
                println!("{}", HELP_MESSAGE);
                return Ok(());
            }
            Action::Reset => {
                self.reset();
                return Ok(());
            }
            _ => {}
        };

        draw_caret();
        self.parse_context()?;

        let mut context = self.ctx.clone().unwrap();
        context.parse()?;
        self.eval()?;

        Ok(())
    }

    pub fn eval(&mut self) -> Result<(), ReplError> {
        todo!()
    }

    pub fn reset(&mut self) {
        self.ctx.take();
        self.state.take();
        self.client_path.take();
    }

    pub fn init(&mut self) -> Result<(), ReplError> {
        self.state.replace(Stronghold::default());

        Ok(())
    }

    pub fn parse_action(&mut self) -> Result<Action, ReplError> {
        let action: Action = read_line()?.try_into()?;
        self.action.replace(action.clone());

        // println(action);

        Ok(action)
    }

    pub fn parse_context(&mut self) -> Result<(), ReplError> {
        let context: Context = (read_line()?).try_into()?;
        self.ctx.replace(context);

        Ok(())
    }

    pub fn parse_client_path(&mut self) -> Result<(), ReplError> {
        let line = read_line()?;
        self.client_path.replace(line);

        Ok(())
    }
}

impl Actionable for Repl {
    type Error = ReplError;

    fn create(&self) -> Result<(), Self::Error> {
        if self.ctx.is_none() {
            return Err(ReplError::UnknownContext);
        }

        let ctx = self.ctx.as_ref().unwrap();

        match ctx {
            Context::Snapshot(_) => {
                let stronghold = self.state.as_ref().unwrap();
                let snapshot_path = match self.ctx.as_ref() {
                    Some(Context::Snapshot(s)) => SnapshotPath::from_path(s.path.as_ref().unwrap()),
                    Some(_) | None => return Err(ReplError::InvalidContext),
                };

                stronghold.commit(&snapshot_path).map_err(|_| ReplError::UnknownValue)?;
            }
            Context::Key(_) => todo!(),
            Context::BIP39 => todo!(),
            Context::SLIP10 => todo!(),
            Context::Store(_) => todo!(),
            Context::None => todo!(),
        }

        Ok(())
    }

    fn read(&self) -> Result<(), Self::Error> {
        todo!()
    }

    fn write(&self) -> Result<(), Self::Error> {
        todo!()
    }

    fn derive(&self) -> Result<(), Self::Error> {
        todo!()
    }

    fn recover(&self) -> Result<(), Self::Error> {
        todo!()
    }
}

fn main() {
    let mut repl = Repl::default();

    // Run the REPL event loop
    loop {
        if let Err(e) = repl.run() {
            println!("{:?}", e);
            continue;
        }
    }
}
