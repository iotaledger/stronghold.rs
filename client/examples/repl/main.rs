// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod command;
mod error;
mod util;

use command::*;
use error::*;
use iota_stronghold::Stronghold;
use std::{cell::RefCell, collections::HashMap, rc::Rc};
use util::*;

pub const HELP_MESSAGE: &str = r#"

░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░▄▀▀░▀█▀▒█▀▄░▄▀▄░█▄░█░▄▀▒░█▄█░▄▀▄░█▒░░█▀▄░░▒█▀▄▒██▀▒█▀▄░█▒░░░░░░░░░
░▄▒░▒░▒░▒░▒▄██░▒█▒░█▀▄░▀▄▀░█▒▀█░▀▄█▒█▒█░▀▄▀▒█▄▄▒█▄▀▒░░█▀▄░█▄▄░█▀▒▒█▄▄▒░▒░▒░░▄
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░


(c) 2020 - 2022 IOTA Stiftung


Stronghold REPL (Read Evaluate Print Loop). This demo program  showcases  the 
basic usage of Stronghold. Only a few commands are featured. The REPL 
maintains a state  of  a Stronghold  instance, that can be modified with some 
commands eg. switching  the client  and  loading  or storing a snapshot file. 

Using the REPL is straightforward. Following commands are  available and self 
documenting. Entering one of the commands will show missing parameters.

The REPL maintains state like the client and the snapshot. 

Commands:
    - help
    - init
    - keygen
    - backup
    - restore
    - slip10gen
    - slip10derive
    - mnemonic
    - bip39restore
    - quit
    - checkrecord
    - checkvault
"#;

/// A [`TermAction`] describe some behavior at the end of execution for each [`Command`].
/// The default for [`TermAction`] is `None` and does nothing. Addtionally a String
/// message can be returned, that will be displayed on the console.
#[derive(Default)]
pub enum TermAction {
    #[default]
    None,

    /// Use this [`TermAction`] to quit the repl
    Quit,

    /// Use this variant to display a message in the terminal
    OkMessage(String),
}

/// A command trait for [`Repl`] commands and their evaluation
pub trait Command {
    /// Evaluates the command with given [`State`]
    fn eval(&self, context: State, parameters: &[String]) -> Result<TermAction, ReplError<String>>;

    /// Validates the number of input tokens, otherwise displays the provided error message
    fn validate(&self, parameter: &Vec<String>) -> Result<(), ReplError<String>> {
        if parameter.len().ne(&self.required_parameters().len()) {
            return Err(ReplError::Invalid(format!(
                "'{}' {}",
                self.name(),
                self.error_message()
            )));
        }

        Ok(())
    }

    /// Returns the name of the command as String
    fn name(&self) -> String;

    /// Returns the number of required parameters
    fn required_parameters(&self) -> Vec<String> {
        Default::default()
    }

    /// Returns the error message for the command
    fn error_message(&self) -> String {
        let plural = |a: usize| match a {
            1 => "",
            _ => "s",
        };
        let req = self.required_parameters();
        format!(
            "requires {} argument{}: {}",
            req.len(),
            plural(req.len()),
            req.join(" ")
        )
    }
}

#[derive(Default, Clone)]
pub struct State {
    stronghold: Rc<RefCell<Option<Stronghold>>>,
    client_path: Rc<RefCell<Vec<u8>>>,
}

#[derive(Default)]
struct Repl {
    state: State,
    bindings: HashMap<String, Box<dyn Command>>,
}

impl Repl {
    /// Creates a command binding with the command as String and an implementation
    /// of [`Command`]
    pub fn bind<C>(&mut self) -> Result<(), ReplError<String>>
    where
        C: Command + Default + 'static,
    {
        let command: C = Default::default();

        if self.bindings.contains_key(&command.name()) {
            return Err(ReplError::Invalid(format!(
                "Command binding already present: '{}'",
                command.name()
            )));
        }
        self.bindings.insert(command.name(), Box::new(command));

        Ok(())
    }

    /// Evaluates a command
    pub fn eval(&self) -> Result<TermAction, ReplError<String>> {
        match readline() {
            Ok(line) => {
                let tk = Tokenizer::try_from(line)?;

                let command = tk.command();
                let bindings = &self.bindings;

                match bindings.get(command).ok_or_else(|| ReplError::Unknown(command.clone())) {
                    Ok(f) => {
                        f.validate(tk.parameter())?;
                        f.eval(self.state.clone(), tk.parameter())
                    }
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Start the repl
    pub fn run(&self) {
        println!("{}", HELP_MESSAGE);

        loop {
            prompt(Some(self.check_initialized()));
            match self.eval() {
                Ok(TermAction::Quit) => break,
                Ok(TermAction::OkMessage(msg)) => {
                    println!("{}", msg);
                }
                Err(e) => {
                    eprintln!("{:?}", e);
                }
                _ => {}
            }
        }
    }

    /// Checks, if the [`REPL`] state has been initialized
    fn check_initialized(&self) -> String {
        let path = self.state.client_path.borrow();
        match path.is_empty() {
            true => "[uninitialized]".to_string(),
            false => "[ready]".to_string(),
        }
    }
}

fn main() {
    let mut repl = Repl::default();

    // create bindings
    if let Err(e) = repl
        .bind::<HelpCommand>()
        .and(repl.bind::<InitCommand>())
        .and(repl.bind::<GenerateKeyCommand>())
        .and(repl.bind::<CheckVaultCommand>())
        .and(repl.bind::<CheckRecordCommand>())
        .and(repl.bind::<BackupCommand>())
        .and(repl.bind::<RestoreCommand>())
        .and(repl.bind::<Slip10GenerateCommand>())
        .and(repl.bind::<Slip10DeriveCommand>())
        .and(repl.bind::<Bip39GenerateCommand>())
        .and(repl.bind::<Bip39RestoreCommand>())
        .and(repl.bind::<QuitCommand>())
    {
        eprintln!("{}", e);
        return;
    }

    repl.run();
}
