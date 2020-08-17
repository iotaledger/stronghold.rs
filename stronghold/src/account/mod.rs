use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use hex;
use std::time::{SystemTime, UNIX_EPOCH};
use bip39;
use bitcoin::network::constants::Network;
use std::str::FromStr;
use bitcoin;

mod subaccount;
mod dummybip39;
use dummybip39::{dummy_mnemonic_to_ed25_seed,dummy_derive};
use bee_signing_ext::binary::ed25519;

pub use subaccount::{SubAccount};

#[derive(Serialize, Deserialize, Debug)]
pub struct Account {
    pub id: String,
    external: bool,
    created_at: u128,
    bip39_mnemonic: String,
    bip39_passphrase: Option<String>,
    pub subaccounts: Vec<SubAccount>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AccountToCreate {
    pub bip39_passphrase: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AccountToImport {
    pub created_at: u128,
    pub bip39_mnemonic: String,
    pub bip39_passphrase: Option<String>,
    pub subaccounts: Vec<SubAccount>
}

pub fn generate_id(bip39_mnemonic: &bip39::Mnemonic, bip39_passphrase: &Option<String>) -> String {
        // Account ID generation: 1/2 : Derive seed into the first address
        let seed;
        if let Some(bip39_passphrase) = bip39_passphrase {
            seed = dummy_mnemonic_to_ed25_seed(bip39_mnemonic, &bip39_passphrase);
        }else{
            seed = dummy_mnemonic_to_ed25_seed(bip39_mnemonic, "");
        }




        let mut extended_private = bitcoin::util::bip32::ExtendedPrivKey::new_master(Network::Bitcoin, seed.as_bytes()).unwrap();
        let secp256k1 = bitcoin::secp256k1::Secp256k1::new();
        let derivation_path = bitcoin::util::bip32::DerivationPath::from_str("m/44'/4218'/0'/0'/0'").unwrap();
        extended_private = extended_private.derive_priv(&secp256k1,&derivation_path).unwrap();
        let extended_public = bitcoin::util::bip32::ExtendedPubKey::from_private(&secp256k1, &extended_private);
        let address = format!("{}",bitcoin::util::address::Address::p2wpkh(&extended_public.public_key, bitcoin::network::constants::Network::Bitcoin));
        
        // Account ID generation: 2/2 : Hash generated address in order to get ID
        let mut hasher = Sha256::new();
        hasher.input(address);
        hex::encode(&hasher.result())
}

impl From<AccountToCreate> for Account {
    fn from(account_to_create: AccountToCreate) -> Self {
        // Mnemonic generation
        let bip39_mnemonic = bip39::Mnemonic::new(bip39::MnemonicType::Words24, bip39::Language::English);

        // ID generation
        let id = generate_id(&bip39_mnemonic, &account_to_create.bip39_passphrase);

        Account {
            id,
            external: false,
            created_at: SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_millis(),
            bip39_mnemonic: String::from(bip39::Mnemonic::new(bip39::MnemonicType::Words24, bip39::Language::English).phrase()),
            bip39_passphrase: account_to_create.bip39_passphrase,
            subaccounts: Vec::new()
        }
    }
}

impl From<AccountToImport> for Account {
    fn from(account_to_import: AccountToImport) -> Self {
        let bip39_mnemonic = bip39::Mnemonic::from_phrase(&account_to_import.bip39_mnemonic, bip39::Language::Spanish).expect("Invalid mnemonic");
        // ID generation
        let id = generate_id(&bip39_mnemonic, &account_to_import.bip39_passphrase);
        Account {
            id,
            external: true,
            created_at: account_to_import.created_at,
            bip39_mnemonic: account_to_import.bip39_mnemonic,
            bip39_passphrase: account_to_import.bip39_passphrase,
            subaccounts: account_to_import.subaccounts,
        }
    }
}

impl Account {

    pub fn new(account_to_create: AccountToCreate) -> Account {
        account_to_create.into()
    }

    pub fn import(account_to_import: AccountToImport) -> Account {
        account_to_import.into()
    }

    fn get_seed(&self) -> Result<bip39::Seed, &'static str> {
        let bip39_mnemonic = bip39::Mnemonic::from_phrase(&self.bip39_mnemonic, bip39::Language::Spanish).unwrap();
        Ok(bip39::Seed::new(&bip39_mnemonic, ""))
    }

    pub fn get_address(&self, path: &str, snapshot_password: &str) -> Result<String, &'static str> {
        let seed = self.get_seed().unwrap();
        let mut extended_private = bitcoin::util::bip32::ExtendedPrivKey::new_master(Network::Bitcoin, seed.as_bytes()).unwrap();
        let secp256k1 = bitcoin::secp256k1::Secp256k1::new();
        let derivation_path = bitcoin::util::bip32::DerivationPath::from_str(path).unwrap();
        extended_private = extended_private.derive_priv(&secp256k1,&derivation_path).unwrap();
        let extended_public = bitcoin::util::bip32::ExtendedPubKey::from_private(&secp256k1, &extended_private);
        Ok(format!("{}",bitcoin::util::address::Address::p2wpkh(&extended_public.public_key, bitcoin::network::constants::Network::Bitcoin)))
    }
    
    pub fn add_subaccount(&mut self, label: String) {
        self.subaccounts.push(SubAccount::new(label))
    }

    

}
