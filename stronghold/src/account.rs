struct Account {
    id: String,
    external: bool,
    created: i64,
    last_decryption: Option<i64>,
    decryption_counter: i32,
    export_counter: i32,
    mnemonic_encrypted: String,
    passphrase_encrypted: Option<String>,
    decryption_password_hashed: String
}


impl Account {

    //Low level fns

    fn new(
        &self,
        id: String,
        external: bool,
        created: i64,
        last_decryption: Option<i64>,
        decryption_counter: i32,
        export_counter: i32,
        mnemonic: String,
        passphrase: Option<String>,
        decryption_password_hashed: String
    ) -> Account {
        Account {
            id: "sha256 of the first address".to_string(),
            external: external,
            created: 154862,
            last_decryption: None,
            decryption_counter: 0,
            export_counter: 0,
            mnemonic_encrypted: mnemonic.to_string(),//encrypt(mnemonic)
            passphrase_encrypted: passphrase,
            decryption_password_hashed: "100xsha256 of the password".to_string()
        }
    }

    //High level fns

    fn import(
        &self,
        created: i64,
        last_decryption: Option<i64>,
        decryption_counter: i32,
        export_counter: i32,
        mnemonic: String,
        passphrase: Option<String>,
        encryption_password: String
    ) -> Account {
        let id = "sha256 of the first address".to_string();
        let external = true;
        let mnemonic_encrypted = mnemonic;
        let passphrase_encrypted = passphrase;
        let decryption_password_hashed = encryption_password;
        return Account::new(&self,id,external,created,last_decryption,decryption_counter,export_counter,mnemonic_encrypted,passphrase_encrypted,decryption_password_hashed);
    }

    fn create(
        &self,
        passphrase: String,
        encryption_password: String
    ) -> Account {
        let id = "IAkdwuj...".to_string();
        let external = false;
        let created = 29384823923;
        let last_decryption = None;
        let decryption_counter = 0;
        let export_counter = 0;
        let mnemonic = "random mnemonic".to_string();
        let mnemonic_encrypted = mnemonic;
        let passphrase_encrypted = Some(passphrase.to_string());
        let decryption_password_hashed = encryption_password;
        return Account::new(&self,id,external,created,last_decryption,decryption_counter,export_counter,mnemonic_encrypted,passphrase_encrypted,decryption_password_hashed);
    }
}