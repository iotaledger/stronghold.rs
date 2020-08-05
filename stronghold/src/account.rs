use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use hex;
use std::time::{SystemTime, UNIX_EPOCH};
use bip39;
use bitcoin::network::constants::Network;
use std::str::FromStr;

#[derive(Serialize, Deserialize, Debug)]
pub struct Account /*Encrypted*/ {
    pub id: String,
    external: bool,
    created_at: u128,
    //last_decryption: Option<usize>,
    //decryption_counter: usize,
    export_counter: usize,
    bip39mnemonic: String,
    //bip39passphrase_encrypted: Option<String>,
    //password_hashed: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct AccountDecrypted {
    id: String,
    external: bool,
    created_at: u128,
    //last_decryption: Option<usize>,
    //decryption_counter: usize,
    export_counter: usize,
    bip39mnemonic: String,
    //bip39passphrase: Option<String>,
    //password: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AccountToCreate;/* {
    //pub bip39passphrase: Option<String>,
//pub password: String,
}*/

#[derive(Serialize, Deserialize, Debug)]
pub struct AccountToImport {
    pub created_at: u128,
    //pub last_decryption: Option<usize>,
    //pub decryption_counter: usize,
    pub export_counter: usize,
    pub bip39mnemonic: String,
    //pub bip39passphrase: Option<String>,
    //pub password: String,
}

impl From<AccountDecrypted> for Account /*Encrypted*/ {
    fn from(account_new: AccountDecrypted) -> Self {
        Account {
            id: account_new.id,
            external: account_new.external,
            created_at: account_new.created_at,
            //last_decryption: None,
            //decryption_counter: account_new.decryption_counter,
            export_counter: account_new.export_counter,
            bip39mnemonic/*_encrypted*/: account_new.bip39mnemonic,//"fn encryptmnemonic(password)".into(),
            //bip39passphrase_encrypted: Some("fn encryptpassphrase(password)".into()),
            //password_hashed: "fn hashpassword(password)".into(),
        }
    }
}

pub fn generate_id(bip39mnemonic: &bip39::Mnemonic) -> String {
        // Account ID generation: 1/2 : Derive seed into the first address
        let seed = bip39::Seed::new(bip39mnemonic, "");
        let mut extended_private = bitcoin::util::bip32::ExtendedPrivKey::new_master(Network::Bitcoin, seed.as_bytes()).unwrap();
        let secp256k1 = bitcoin::secp256k1::Secp256k1::new();
        let derivation_path = bitcoin::util::bip32::DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap();
        extended_private = extended_private.derive_priv(&secp256k1,&derivation_path).unwrap();
        let extended_public = bitcoin::util::bip32::ExtendedPubKey::from_private(&secp256k1, &extended_private);
        let address = format!("{}",bitcoin::util::address::Address::p2wpkh(&extended_public.public_key, bitcoin::network::constants::Network::Bitcoin));
        
        // Account ID generation: 2/2 : Hash generated address in order to get ID
        let mut hasher = Sha256::new();
        hasher.update(address);
        hex::encode(&hasher.finalize())
}

impl From<AccountToCreate> for AccountDecrypted {
    fn from(account_to_create: AccountToCreate) -> Self {
        // Mnemonic generation
        let bip39mnemonic = bip39::Mnemonic::new(bip39::MnemonicType::Words24, bip39::Language::English);
        let bip39mnemonic_str = String::from(bip39mnemonic.phrase());

        // ID generation
        let id = generate_id(&bip39mnemonic);

        AccountDecrypted {
            id,
            external: false,
            created_at: SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_millis(),
            //last_decryption: None,
            //decryption_counter: 0,
            export_counter: 0,
            bip39mnemonic: String::from(bip39::Mnemonic::new(bip39::MnemonicType::Words24, bip39::Language::English).phrase()),
            //bip39passphrase: account_to_create.bip39passphrase,
            //password: account_to_create.password,
        }
    }
}

impl From<AccountToImport> for AccountDecrypted {
    fn from(account_to_import: AccountToImport) -> Self {
        let bip39mnemonic = bip39::Mnemonic::from_phrase(&account_to_import.bip39mnemonic, bip39::Language::Spanish).expect("Invalid mnemonic");
        // ID generation
        let id = generate_id(&bip39mnemonic);
        AccountDecrypted {
            id,
            external: true,
            created_at: account_to_import.created_at,
            //last_decryption: None,
            //decryption_counter: account_to_import.decryption_counter,
            export_counter: account_to_import.export_counter,
            bip39mnemonic: account_to_import.bip39mnemonic,
            //bip39passphrase: account_to_import.bip39passphrase,
            //password: account_to_import.password,
        }
    }
}

impl Account /*Encrypted*/ {
    //Low level fns

    fn new(account_new: AccountDecrypted) -> Result<Account /*Encrypted*/, &'static str> {
        Ok(account_new.into())
    }

    //High level fns

    pub fn import(account_to_import: AccountToImport) -> Result<Account /*Encrypted*/, &'static str> {
        let account_new: AccountDecrypted = account_to_import.into();
        Ok(account_new.into())
    }

    pub fn create(account_to_create: AccountToCreate) -> Result<Account /*Encrypted*/, &'static str> {
        let account_new: AccountDecrypted = account_to_create.into();
        Ok(account_new.into())
    }

    pub fn get_seed(&self) -> Result<bip39::Seed, &'static str> {
        let bip39mnemonic = bip39::Mnemonic::from_phrase(&self.bip39mnemonic, bip39::Language::Spanish).unwrap();
        Ok(bip39::Seed::new(&bip39mnemonic, ""))
    }

    pub fn get_address(&self, account_id: &str, path: &str, snapshot_password: &str) -> Result<String, &'static str> {
        let seed = self.get_seed().unwrap();
        let mut extended_private = bitcoin::util::bip32::ExtendedPrivKey::new_master(Network::Bitcoin, seed.as_bytes()).unwrap();
        let secp256k1 = bitcoin::secp256k1::Secp256k1::new();
        let derivation_path = bitcoin::util::bip32::DerivationPath::from_str(path).unwrap();
        extended_private = extended_private.derive_priv(&secp256k1,&derivation_path).unwrap();
        let extended_public = bitcoin::util::bip32::ExtendedPubKey::from_private(&secp256k1, &extended_private);
        Ok(format!("{}",bitcoin::util::address::Address::p2wpkh(&extended_public.public_key, bitcoin::network::constants::Network::Bitcoin)))
    }
    
}
