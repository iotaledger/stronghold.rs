struct Account {
    id: String,
    external: bool,
    created_at: i64,
    last_decryption: Option<i64>,
    decryption_counter: i32,
    export_counter: i32,
    bip39mnemonic_encrypted: String,
    bip39passphrase_encrypted: Option<String>,
    password_hashed: String,
}

struct AccountNew {
    id: String,
    external: bool,
    created_at: i64,
    last_decryption: Option<i64>,
    decryption_counter: i32,
    export_counter: i32,
    bip39mnemonic: String,
    bip39passphrase: Option<String>,
    password: String,
}

impl From<AccountNew> for Account {
    fn from(account_new: AccountNew) -> Self {
        Account {
            id: account_new.id,
            external: account_new.external,
            created_at: account_new.created_at,
            last_decryption: None,
            decryption_counter: account_new.decryption_counter,
            export_counter: account_new.export_counter,
            bip39mnemonic_encrypted: "fn encryptmnemonic(password)".into(),
            bip39passphrase_encrypted: Some("fn encryptpassphrase(password)".into()),
            password_hashed: "fn hashpassword(password)".into(),
        }
    }
}

struct AccountToCreate {
    bip39passphrase: Option<String>,
    password: String,
}

impl From<AccountToCreate> for AccountNew {
    fn from(account_to_create: AccountToCreate) -> Self {
        AccountNew {
            id: "fn sha256(address m44/0'/0'/0/0)".to_string(),
            external: false,
            created_at: 0, //fn get_time()
            last_decryption: None,
            decryption_counter: 0,
            export_counter: 0,
            bip39mnemonic: "fn generate_mnemonic()".to_string(),
            bip39passphrase: account_to_create.bip39passphrase,
            password: account_to_create.password,
        }
    }
}

struct AccountToImport {
    created_at: i64,
    last_decryption: Option<i64>,
    decryption_counter: i32,
    export_counter: i32,
    bip39mnemonic: String,
    bip39passphrase: Option<String>,
    password: String,
}

impl From<AccountToImport> for AccountNew {
    fn from(account_to_import: AccountToImport) -> Self {
        AccountNew {
            id: "fn sha256(address m44/0'/0'/0/0)".to_string(),
            external: false,
            created_at: account_to_import.created_at,
            last_decryption: None,
            decryption_counter: account_to_import.decryption_counter,
            export_counter: account_to_import.export_counter,
            bip39mnemonic: account_to_import.bip39mnemonic,
            bip39passphrase: account_to_import.bip39passphrase,
            password: account_to_import.password,
        }
    }
}

impl Account {
    //Low level fns

    fn new(&self, account_new: AccountNew) -> Account {
        account_new.into()
    }

    //High level fns

    fn import(&self, account_to_import: AccountToImport) -> Account {
        let account_new: AccountNew = account_to_import.into();
        account_new.into()
    }

    fn create(&self, account_to_create: AccountToCreate) -> Account {
        let account_new: AccountNew = account_to_create.into();
        account_new.into()
    }
}
