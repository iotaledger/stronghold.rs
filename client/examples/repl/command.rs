// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
#![allow(deprecated)]

use std::ops::Deref;

use crate::{
    error::ReplError,
    util::{parse_keytype, parse_lang},
    Command, State, TermAction, HELP_MESSAGE,
};
use iota_stronghold::{
    procedures::{BIP39Generate, BIP39Recover, Chain, GenerateKey, Slip10Derive, Slip10DeriveInput, Slip10Generate},
    KeyProvider, Location, SnapshotPath, Stronghold,
};

/// This command display a help message
#[derive(Default)]
pub struct HelpCommand;
impl Command for HelpCommand {
    fn eval(&self, _: State, _: &[String]) -> Result<TermAction, ReplError<String>> {
        println!("{}", HELP_MESSAGE);
        Ok(Default::default())
    }

    fn name(&self) -> String {
        "help".to_string()
    }

    fn validate(&self, _parameter: &Vec<String>) -> Result<(), ReplError<String>> {
        Ok(())
    }
}

#[derive(Default)]
pub struct InitCommand;
impl Command for InitCommand {
    fn eval(&self, context: State, parameters: &[String]) -> Result<TermAction, ReplError<String>> {
        let mut stronghold = context.stronghold.borrow_mut();
        stronghold.replace(Stronghold::default());

        let r = context.client_path;

        let mut client_path = r.borrow_mut();
        client_path.clear();
        client_path.extend_from_slice(parameters[0].as_bytes());

        stronghold
            .as_ref()
            .unwrap()
            .create_client(client_path.deref().clone())?;

        Ok(Default::default())
    }

    fn name(&self) -> String {
        "init".to_string()
    }

    fn required_parameters(&self) -> Vec<String> {
        vec!["<client_path>"].into_iter().map(ToOwned::to_owned).collect()
    }
}

#[derive(Default)]
pub struct GenerateKeyCommand;
impl Command for GenerateKeyCommand {
    fn eval(&self, context: State, parameters: &[String]) -> Result<TermAction, ReplError<String>> {
        let stronghold = match context.stronghold.borrow().clone() {
            Some(s) => s,
            None => return Err(ReplError::Invalid("System not initialized. Run init".to_owned())),
        };
        let client_path = context.client_path.borrow();

        let key_type = parse_keytype(&parameters[0])?;
        let vault_path = &parameters[1];
        let record_path = &parameters[2];
        let client = stronghold.get_client(client_path.deref())?;

        // execute the procedure
        client.execute_procedure(GenerateKey {
            ty: key_type,
            output: Location::const_generic(vault_path.clone().into_bytes(), record_path.clone().into_bytes()),
        })?;

        Ok(TermAction::OkMessage("Key stored sucessfully".to_string()))
    }

    fn name(&self) -> String {
        "keygen".to_string()
    }

    fn required_parameters(&self) -> Vec<String> {
        vec!["<key_type>", "<vault_path>", "<record_path>"]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect()
    }
}

#[derive(Default)]
pub struct CheckVaultCommand;
impl Command for CheckVaultCommand {
    fn eval(&self, context: State, parameters: &[String]) -> Result<TermAction, ReplError<String>> {
        let stronghold = match context.stronghold.borrow().clone() {
            Some(s) => s,
            None => return Err(ReplError::Invalid("System not initialized. Run init".to_owned())),
        };
        let client_path = context.client_path.borrow();

        let client = stronghold.get_client(client_path.deref())?;
        let vault_path = &parameters[0];

        match client.vault_exists(vault_path) {
            Ok(exists) => {
                println!("Vault exists? {}", if exists { "yes" } else { "no" });
            }
            Err(e) => return Err(e.into()),
        }

        Ok(Default::default())
    }

    fn name(&self) -> String {
        "checkvault".to_string()
    }

    fn required_parameters(&self) -> Vec<String> {
        vec!["<vault_path>"].into_iter().map(ToOwned::to_owned).collect()
    }
}

#[derive(Default)]
pub struct CheckRecordCommand;
impl Command for CheckRecordCommand {
    fn eval(&self, context: State, parameters: &[String]) -> Result<TermAction, ReplError<String>> {
        let stronghold = match context.stronghold.borrow().clone() {
            Some(s) => s,
            None => return Err(ReplError::Invalid("System not initialized. Run init".to_owned())),
        };
        let client_path = context.client_path.borrow();
        let client = stronghold.get_client(client_path.deref())?;

        let vault_path = &parameters[0];
        let record_path = &parameters[1];

        match client.record_exists(&Location::const_generic(
            vault_path.clone().into_bytes(),
            record_path.clone().into_bytes(),
        )) {
            Ok(exists) => {
                println!("Record exists? {}", if exists { "yes" } else { "no" });
            }
            Err(e) => return Err(e.into()),
        }

        Ok(Default::default())
    }

    fn name(&self) -> String {
        "checkrecord".to_string()
    }

    fn required_parameters(&self) -> Vec<String> {
        vec!["<vault_path>", "<record_path>"]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect()
    }
}

#[derive(Default)]
pub struct BackupCommand;
impl Command for BackupCommand {
    fn eval(&self, context: State, parameters: &[String]) -> Result<TermAction, ReplError<String>> {
        let stronghold = match context.stronghold.borrow().clone() {
            Some(s) => s,
            None => return Err(ReplError::Invalid("System not initialized. Run init".to_owned())),
        };
        let password = parameters[1].clone().as_bytes().to_vec();
        let snapshot_path = SnapshotPath::from_path(&parameters[0]);
        let keyprovider = KeyProvider::with_passphrase_truncated(password)?;

        stronghold.commit_with_keyprovider(&snapshot_path, &keyprovider)?;

        Ok(TermAction::OkMessage(
            "Stronghold snapshot successfully written to disk".to_string(),
        ))
    }

    fn name(&self) -> String {
        "backup".to_string()
    }

    fn required_parameters(&self) -> Vec<String> {
        vec!["<path_to_snapshot_location>", "<passphrase>"]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect()
    }
}

#[derive(Default)]
pub struct RestoreCommand;
impl Command for RestoreCommand {
    fn eval(&self, context: State, parameters: &[String]) -> Result<TermAction, ReplError<String>> {
        let stronghold = match context.stronghold.borrow().clone() {
            Some(s) => s,
            None => return Err(ReplError::Invalid("System not initialized. Run init".to_owned())),
        };
        let password = parameters[1].clone().as_bytes().to_vec();
        let snapshot_path = SnapshotPath::from_path(&parameters[0]);
        let keyprovider = KeyProvider::with_passphrase_truncated(password)?;

        stronghold.load_snapshot(&keyprovider, &snapshot_path)?;

        Ok(TermAction::OkMessage(
            "Stronghold snapshot successfully loaded from disk".to_string(),
        ))
    }

    fn name(&self) -> String {
        "restore".to_string()
    }

    fn required_parameters(&self) -> Vec<String> {
        vec!["<path_to_snapshot_location>", "<passphrase>"]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect()
    }
}

#[derive(Default)]
pub struct Slip10GenerateCommand;
impl Command for Slip10GenerateCommand {
    fn eval(&self, context: State, parameters: &[String]) -> Result<TermAction, ReplError<String>> {
        let stronghold = match context.stronghold.borrow().clone() {
            Some(s) => s,
            None => return Err(ReplError::Invalid("System not initialized. Run init".to_owned())),
        };
        let client_path = context.client_path.borrow();
        let client = stronghold.get_client(client_path.deref())?;

        let vault_path = &parameters[0];
        let record_path = &parameters[1];

        client.execute_procedure(Slip10Generate {
            size_bytes: None,
            output: Location::const_generic(vault_path.clone().into_bytes(), record_path.clone().into_bytes()),
        })?;

        Ok(TermAction::OkMessage(format!(
            "Created seed at location: {} - {}",
            vault_path, record_path
        )))
    }

    fn name(&self) -> String {
        "slip10gen".to_string()
    }

    fn required_parameters(&self) -> Vec<String> {
        vec!["<vault_path>", "<record_path>"]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect()
    }
}

#[derive(Default)]
pub struct Slip10DeriveCommand;
impl Command for Slip10DeriveCommand {
    fn eval(&self, context: State, parameters: &[String]) -> Result<TermAction, ReplError<String>> {
        let stronghold = match context.stronghold.borrow().clone() {
            Some(s) => s,
            None => return Err(ReplError::Invalid("System not initialized. Run init".to_owned())),
        };
        let client_path = context.client_path.borrow();
        let client = stronghold.get_client(client_path.deref())?;

        let chain_code = &parameters[0];
        let vault_path_old = &parameters[1];
        let record_path_old = &parameters[2];
        let vault_path_new = &parameters[3];
        let record_path_new = &parameters[4];

        client.execute_procedure(Slip10Derive {
            chain: Chain::from_u32_hardened(chain_code.parse()),
            input: Slip10DeriveInput::Seed(Location::const_generic(
                vault_path_old.clone().into_bytes(),
                record_path_old.clone().into_bytes(),
            )),
            output: Location::const_generic(
                vault_path_new.clone().into_bytes(),
                record_path_new.clone().into_bytes(),
            ),
        })?;

        Ok(TermAction::OkMessage(format!(
            "Derived key and stored at location: {} - {}",
            vault_path_new, record_path_new
        )))
    }

    fn name(&self) -> String {
        "slip10derive".to_string()
    }

    fn required_parameters(&self) -> Vec<String> {
        vec![
            "<chain>",
            "<vault_path_origin>",
            "<record_path_origin>",
            "<vault_path_derive>",
            "<record_path_derive>",
        ]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect()
    }
}

#[derive(Default)]
pub struct Bip39GenerateCommand;
impl Command for Bip39GenerateCommand {
    fn eval(&self, context: State, parameters: &[String]) -> Result<TermAction, ReplError<String>> {
        let stronghold = match context.stronghold.borrow().clone() {
            Some(s) => s,
            None => return Err(ReplError::Invalid("System not initialized. Run init".to_owned())),
        };
        let client_path = context.client_path.borrow();
        let client = stronghold.get_client(client_path.deref())?;

        let password = &parameters[0];
        let language = &parameters[1];
        let vault_path = &parameters[2];
        let record_path = &parameters[3];

        let result = client.execute_procedure(BIP39Generate {
            passphrase: Some(password.clone()),
            language: parse_lang(language)?,
            output: Location::const_generic(vault_path.clone().into_bytes(), record_path.clone().into_bytes()),
        })?;

        Ok(TermAction::OkMessage(format!("Generated Mnemonic : {}", result)))
    }

    fn name(&self) -> String {
        "mnemonic".to_string()
    }

    fn required_parameters(&self) -> Vec<String> {
        vec!["<passphrase>", "<language>", "<vault_path>", "<record_path>"]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect()
    }
}

#[derive(Default)]
pub struct Bip39RestoreCommand;
impl Command for Bip39RestoreCommand {
    fn eval(&self, context: State, parameters: &[String]) -> Result<TermAction, ReplError<String>> {
        let stronghold = match context.stronghold.borrow().clone() {
            Some(s) => s,
            None => return Err(ReplError::Invalid("System not initialized. Run init".to_owned())),
        };
        let client_path = context.client_path.borrow();
        let client = stronghold.get_client(client_path.deref())?;

        let password = &parameters[0];
        let mnemonic = &parameters[1];
        let vault_path = &parameters[2];
        let record_path = &parameters[3];

        client.execute_procedure(BIP39Recover {
            passphrase: Some(password.clone()),
            mnemonic: mnemonic.clone(),
            output: Location::const_generic(vault_path.clone().into_bytes(), record_path.clone().into_bytes()),
        })?;

        Ok(Default::default())
    }

    fn name(&self) -> String {
        "bip39restore".to_string()
    }

    fn required_parameters(&self) -> Vec<String> {
        vec![
            "<passphrase>",
            "<language>",
            "<vault_path_origin>",
            "<record_path_origin>",
            "<vault_path_derive>",
            "<record_path_derive>",
        ]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect()
    }
}

#[derive(Default)]
pub struct QuitCommand;
impl Command for QuitCommand {
    fn eval(&self, _: State, _: &[String]) -> Result<TermAction, ReplError<String>> {
        Ok(TermAction::Quit)
    }

    fn name(&self) -> String {
        "quit".to_string()
    }
}
