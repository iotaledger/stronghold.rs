// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

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

    fn required_param_length(&self) -> usize {
        1
    }

    fn error_message(&self) -> String {
        "requires one argument: <client_path>".to_string()
    }
}

#[derive(Default)]
pub struct GenerateKeyCommand;
impl Command for GenerateKeyCommand {
    fn eval(&self, context: State, parameters: &[String]) -> Result<TermAction, ReplError<String>> {
        let stronghold = context.stronghold.borrow().clone().unwrap();
        let client_path = context.client_path.borrow();

        let kt = parse_keytype(&parameters[0])?;
        let vp = &parameters[1];
        let rp = &parameters[2];
        let client = stronghold.get_client(client_path.deref())?;

        // execute the procedure
        client.execute_procedure(GenerateKey {
            ty: kt,
            output: Location::const_generic(vp.clone().into_bytes(), rp.clone().into_bytes()),
        })?;

        Ok(TermAction::OkMessage("Key stored sucessfully".to_string()))
    }

    fn name(&self) -> String {
        "keygen".to_string()
    }

    fn required_param_length(&self) -> usize {
        3
    }

    fn error_message(&self) -> String {
        "requires three arguments: <key_type> <vault_path> <record_path>".to_string()
    }
}

#[derive(Default)]
pub struct CheckVaultCommand;
impl Command for CheckVaultCommand {
    fn eval(&self, context: State, parameters: &[String]) -> Result<TermAction, ReplError<String>> {
        let stronghold = context.stronghold.borrow().clone().unwrap();
        let client_path = context.client_path.borrow();

        let client = stronghold.get_client(client_path.deref())?;
        let vp = &parameters[0];

        match client.vault_exists(vp) {
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

    fn required_param_length(&self) -> usize {
        1
    }

    fn error_message(&self) -> String {
        "requires one argument: <vault_path>".to_string()
    }
}

#[derive(Default)]
pub struct CheckRecordCommand;
impl Command for CheckRecordCommand {
    fn eval(&self, context: State, parameters: &[String]) -> Result<TermAction, ReplError<String>> {
        let stronghold = context.stronghold.borrow().clone().unwrap();
        let client_path = context.client_path.borrow();
        let client = stronghold.get_client(client_path.deref())?;

        let vp = &parameters[1];
        let rp = &parameters[2];

        match client.record_exists(&Location::const_generic(
            vp.clone().into_bytes(),
            rp.clone().into_bytes(),
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

    fn required_param_length(&self) -> usize {
        2
    }

    fn error_message(&self) -> String {
        "requires two arguments: <vault_path> <record_path>".to_string()
    }
}

#[derive(Default)]
pub struct BackupCommand;
impl Command for BackupCommand {
    fn eval(&self, context: State, parameters: &[String]) -> Result<TermAction, ReplError<String>> {
        let stronghold = context.stronghold.borrow().clone().unwrap();
        let pw = parameters[1].clone().as_bytes().to_vec();
        let pa = SnapshotPath::from_path(&parameters[0]);
        let ky = KeyProvider::with_passphrase_truncated(pw)?;

        stronghold.commit_with_keyprovider(&pa, &ky)?;

        Ok(TermAction::OkMessage(
            "Stronghold snapshot successfully written to disk".to_string(),
        ))
    }

    fn name(&self) -> String {
        "backup".to_string()
    }

    fn required_param_length(&self) -> usize {
        2
    }

    fn error_message(&self) -> String {
        "requires two arguments: <path_to_snapshot_location> <passphrase>".to_string()
    }
}

#[derive(Default)]
pub struct RestoreCommand;
impl Command for RestoreCommand {
    fn eval(&self, context: State, parameters: &[String]) -> Result<TermAction, ReplError<String>> {
        let stronghold = context.stronghold.borrow().clone().unwrap();
        let pw = parameters[1].clone().as_bytes().to_vec();
        let pa = SnapshotPath::from_path(&parameters[0]);
        let ky = KeyProvider::with_passphrase_truncated(pw)?;

        stronghold.load_snapshot(&ky, &pa)?;

        Ok(TermAction::OkMessage(
            "Stronghold snapshot successfully loaded from disk".to_string(),
        ))
    }

    fn name(&self) -> String {
        "restore".to_string()
    }

    fn required_param_length(&self) -> usize {
        2
    }

    fn error_message(&self) -> String {
        "requires two arguments: <path_to_snapshot_location> <passphrase>".to_string()
    }
}

#[derive(Default)]
pub struct Slip10GenerateCommand;
impl Command for Slip10GenerateCommand {
    fn eval(&self, context: State, parameters: &[String]) -> Result<TermAction, ReplError<String>> {
        let stronghold = context.stronghold.borrow().clone().unwrap();
        let client_path = context.client_path.borrow();
        let client = stronghold.get_client(client_path.deref())?;

        let vp = &parameters[0];
        let rp = &parameters[1];

        client.execute_procedure(Slip10Generate {
            size_bytes: None,
            output: Location::const_generic(vp.clone().into_bytes(), rp.clone().into_bytes()),
        })?;

        Ok(TermAction::OkMessage(format!(
            "Created seed at location: {} - {}",
            vp, rp
        )))
    }

    fn name(&self) -> String {
        "slip10gen".to_string()
    }

    fn required_param_length(&self) -> usize {
        2
    }

    fn error_message(&self) -> String {
        "requires two arguments: <vault_path> <record_path>".to_string()
    }
}

#[derive(Default)]
pub struct Slip10DeriveCommand;
impl Command for Slip10DeriveCommand {
    fn eval(&self, context: State, parameters: &[String]) -> Result<TermAction, ReplError<String>> {
        let stronghold = context.stronghold.borrow().clone().unwrap();
        let client_path = context.client_path.borrow();
        let client = stronghold.get_client(client_path.deref())?;

        let ccd = &parameters[0];
        let vpo = &parameters[1];
        let rpo = &parameters[2];
        let vpn = &parameters[3];
        let rpn = &parameters[4];

        client.execute_procedure(Slip10Derive {
            chain: Chain::from_u32_hardened(ccd.parse()),
            input: Slip10DeriveInput::Seed(Location::const_generic(
                vpo.clone().into_bytes(),
                rpo.clone().into_bytes(),
            )),
            output: Location::const_generic(vpn.clone().into_bytes(), rpn.clone().into_bytes()),
        })?;

        Ok(TermAction::OkMessage(format!(
            "Derived key and stored at location: {} - {}",
            vpn, rpn
        )))
    }

    fn name(&self) -> String {
        "slip10derive".to_string()
    }

    fn required_param_length(&self) -> usize {
        5
    }

    fn error_message(&self) -> String {
        "requires two arguments: <chain> <vault_path_origin> <record_path_origin> <vault_path_derive> <record_path_derive>"
            .to_string()
    }
}

#[derive(Default)]
pub struct Bip39GenerateCommand;
impl Command for Bip39GenerateCommand {
    fn eval(&self, context: State, parameters: &[String]) -> Result<TermAction, ReplError<String>> {
        let stronghold = context.stronghold.borrow().clone().unwrap();
        let client_path = context.client_path.borrow();
        let client = stronghold.get_client(client_path.deref())?;

        let pw = &parameters[0];
        let lg = &parameters[1];
        let vp = &parameters[2];
        let rc = &parameters[3];

        let result = client.execute_procedure(BIP39Generate {
            passphrase: Some(pw.clone()),
            language: parse_lang(lg)?,
            output: Location::const_generic(vp.clone().into_bytes(), rc.clone().into_bytes()),
        })?;

        Ok(TermAction::OkMessage(format!("Generated Mnemonic : {}", result)))
    }

    fn name(&self) -> String {
        "mnemonic".to_string()
    }

    fn required_param_length(&self) -> usize {
        4
    }

    fn error_message(&self) -> String {
        "requires four arguments: <passphrase> <language> <vault_path> <record_path>".to_string()
    }
}

#[derive(Default)]
pub struct Bip39RestoreCommand;
impl Command for Bip39RestoreCommand {
    fn eval(&self, context: State, parameters: &[String]) -> Result<TermAction, ReplError<String>> {
        let stronghold = context.stronghold.borrow().clone().unwrap();
        let client_path = context.client_path.borrow();
        let client = stronghold.get_client(client_path.deref())?;

        let pw = &parameters[0];
        let mn = &parameters[1];
        let vp = &parameters[2];
        let rc = &parameters[3];

        client.execute_procedure(BIP39Recover {
            passphrase: Some(pw.clone()),
            mnemonic: mn.clone(),
            output: Location::const_generic(vp.clone().into_bytes(), rc.clone().into_bytes()),
        })?;

        Ok(Default::default())
    }

    fn name(&self) -> String {
        "bip39restore".to_string()
    }

    fn required_param_length(&self) -> usize {
        4
    }

    fn error_message(&self) -> String {
        "requires 3 arguments: <passphrase> <language> <vault_path_origin> <record_path_origin> <vault_path_derive> <record_path_derive>"
        .to_string()
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
