use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Account /*Encrypted*/ {
    pub id: String,
    external: bool,
    created_at: u64,
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
    created_at: u64,
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
    pub created_at: u64,
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

impl From<AccountToCreate> for AccountDecrypted {
    fn from(account_to_create: AccountToCreate) -> Self {
        AccountDecrypted {
            id: "fn sha256(address m44/0'/0'/0/0)".to_string(),
            external: false,
            created_at: 0, //fn get_time()
            //last_decryption: None,
            //decryption_counter: 0,
            export_counter: 0,
            bip39mnemonic: "fn generate_mnemonic()".to_string(),
            //bip39passphrase: account_to_create.bip39passphrase,
            //password: account_to_create.password,
        }
    }
}

impl From<AccountToImport> for AccountDecrypted {
    fn from(account_to_import: AccountToImport) -> Self {
        AccountDecrypted {
            id: "fn sha256(address m44/0'/0'/0/0)".to_string(),
            external: false,
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
}
