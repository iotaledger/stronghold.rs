// Copyright 2020 IOTA Stiftung
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

mod dummybip39;
use anyhow::{anyhow, Context, Result};
use bee_signing_ext::{
    binary::{ed25519, BIP32Path},
    Signer,
};
use dummybip39::{dummy_derive_into_address, dummy_mnemonic_to_ed25_seed};

#[derive(Serialize, Deserialize, Debug)]
/// Account
///
/// Contains a bip39 master seed: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
///
/// # Properties
///
/// `id`: identifier deterministically generated hashing with sha256 the first receiving address of its first sub
/// account (bip39 account)
///
/// `external`: true if the account was imported from outside or false if was created in stronghold
///
/// `created_at`: timestamp in unix epoch in ms when the account was created
///
/// `last_updated_on`: timestamp in unix epoch in ms of when the account was updated for last time
///
/// `bip39_mnemonic`: human readable bip39 mnemonic phrase. Critical data to have, don't forget it.
///
/// `bip39_passphrase`: passphrase used to salt the menmonic phrase, optional but critical if is used. Don't forget it.
///
/// # Considerations
///
/// This struct doesn't handle data in the snapshot. Be careful when you use it.
pub struct Account {
    id: [u8; 32],
    external: bool,
    created_at: u128,
    last_updated_on: u128,
    bip39_mnemonic: String,
    bip39_passphrase: Option<String>,
}

fn generate_id<'a>(bip39_mnemonic: &str, bip39_passphrase: &Option<String>) -> Result<[u8; 32]> {
    // Account ID generation: 1/2 : Derive seed into the first address
    let seed;
    if let Some(bip39_passphrase) = bip39_passphrase {
        seed = dummy_mnemonic_to_ed25_seed(bip39_mnemonic, &bip39_passphrase);
    } else {
        seed = dummy_mnemonic_to_ed25_seed(bip39_mnemonic, "");
    }
    let privkey =
        ed25519::Ed25519PrivateKey::generate_from_seed(&seed, &BIP32Path::from_str("m/44H/4218H/0H/0H").unwrap())
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let address = dummy_derive_into_address(privkey);

    // Account ID generation: 2/2 : Hash generated address in order to get ID
    let mut hasher = Sha256::new();
    hasher.input(address);
    Ok(hasher.result().into())
}

impl Account {
    /// Instanciates a new Account{}
    ///
    /// The new account will have internally a random mnemonic and the current date
    ///
    /// # Parameters
    ///
    /// `bip39_passphrase`: passphrase used to salt the menmonic phrase, optional but critical if is used. Don't forget
    /// it.
    ///
    /// # Examples
    /// ```
    /// use stronghold::Account;
    /// let account = Account::new(None).unwrap();
    /// ```
    /// ```
    /// use stronghold::Account;
    /// let bip39_passphrase = Some("banana".to_string());
    /// let account = Account::new(bip39_passphrase).unwrap();
    /// ```
    pub fn new(bip39_passphrase: Option<String>) -> Result<Account> {
        // Mnemonic generation
        let bip39_mnemonic = bip39::Mnemonic::new(bip39::MnemonicType::Words24, bip39::Language::English);

        // ID generation
        let id = generate_id(&bip39_mnemonic.phrase(), &bip39_passphrase)?;
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("Time went backwards")?
            .as_millis();
        let last_updated_on = created_at;
        Ok(Account {
            id,
            external: false,
            created_at,
            last_updated_on,
            bip39_mnemonic: bip39_mnemonic.into_phrase(),
            bip39_passphrase,
        })
    }

    /// Instanciates a new Account{} from given data
    ///
    /// The account will have the given data
    ///
    /// # Parameters
    ///
    /// `created_at`: timestamp in unix epoch in ms when the account was created (optional, None will internally set
    /// current timestamp)
    ///
    /// `last_updated_on`: timestamp in unix epoch in ms of when the account was updated for last time (optional, None
    /// will internally set current timestamp)
    ///
    /// `bip39_mnemonic`: human readable bip39 mnemonic phrase. Critical data to have, don't forget it.
    ///
    /// `bip39_passphrase`: passphrase used to salt the menmonic phrase, optional but critical if is used. Don't forget
    /// it.
    ///
    /// # Example
    /// ```
    /// use stronghold::Account;
    /// let created_at = Some(1598890069000);
    /// let last_updated_on = Some(1598890070000);
    /// let mnemonic = "gossip region recall forest clip confirm agent grant border spread under lyrics diesel hint mind patch oppose large street panther duty robust city wedding";
    ///
    /// let account = Account::import(created_at, last_updated_on, mnemonic.to_string(), None).unwrap();
    /// ```
    pub fn import(
        created_at: Option<u128>,
        last_updated_on: Option<u128>,
        bip39_mnemonic: String,
        bip39_passphrase: Option<String>,
    ) -> Result<Account> {
        if bip39::Mnemonic::from_phrase(&bip39_mnemonic, bip39::Language::English).is_err() {
            return Err(anyhow!("Invalid mnemonic"));
        };
        // ID generation
        let id = generate_id(&bip39_mnemonic, &bip39_passphrase)?;

        let created_at = if let Some(created_at) = created_at {
            created_at
        } else {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("Time went backwards")?
                .as_millis()
        };
        let last_updated_on = if let Some(last_updated_on) = last_updated_on {
            last_updated_on
        } else {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("Time went backwards")?
                .as_millis()
        };

        Ok(Account {
            id,
            external: true,
            created_at,
            last_updated_on,
            bip39_mnemonic,
            bip39_passphrase,
        })
    }

    pub(crate) fn get_seed(&self) -> ed25519::Ed25519Seed {
        let bip39_passphrase = match &self.bip39_passphrase {
            Some(x) => x,
            None => "",
        };
        dummy_mnemonic_to_ed25_seed(&self.bip39_mnemonic, &bip39_passphrase)
    }

    fn get_privkey(&self, derivation_path: String) -> Result<ed25519::Ed25519PrivateKey> {
        let seed = self.get_seed();
        Ok(ed25519::Ed25519PrivateKey::generate_from_seed(
            &seed,
            &BIP32Path::from_str(&derivation_path).map_err(|e| anyhow::anyhow!(e.to_string()))?,
        )
        .map_err(|e| anyhow::anyhow!(e.to_string()))?)
    }

    /// Derives the account seed returning an address
    ///
    /// # Parameters
    ///
    /// `derivation_path`: path required that will be used for derive the seed.
    ///
    /// # Returns
    /// string with bech32 encoded public key
    ///
    /// # Example
    /// ```
    /// use stronghold::Account;
    /// let mnemonic = "gossip region recall forest clip confirm agent grant border spread under lyrics diesel hint mind patch oppose large street panther duty robust city wedding";
    /// let account = Account::import(None, None, mnemonic.to_string(), None).unwrap();
    /// let derivation_path = "m/44H/4218H/0H/0H/0H".to_string();
    ///
    /// let address = account.get_address(derivation_path);
    /// ```
    pub fn get_address(&self, derivation_path: String) -> Result<String> {
        let privkey = self.get_privkey(derivation_path)?;
        Ok(dummy_derive_into_address(privkey))
    }

    /// Signs a message with a derived private key from the account seed
    ///
    /// # Parameters
    ///
    /// `derivation_path`: path required that will be used for derive the seed.
    ///
    /// # Returns
    /// signature as an u8 slice
    ///
    /// # Example
    /// ```
    /// use stronghold::Account;
    /// let mnemonic = "gossip region recall forest clip confirm agent grant border spread under lyrics diesel hint mind patch oppose large street panther duty robust city wedding";
    /// let account = Account::import(None, None, mnemonic.to_string(), None).unwrap();
    /// let message = "banana".as_bytes();
    /// let derivation_path = "m/44H/4218H/0H/0H/0H".to_string();
    ///
    /// let signature = account.sign_message(message,derivation_path);
    /// ```
    pub fn sign_message(&self, message: &[u8], derivation_path: String) -> Result<[u8; 64]> {
        let privkey = self.get_privkey(derivation_path)?;
        Ok(privkey.sign(message).to_bytes())
    }

    /// Returns the account identifier
    ///
    /// # Example
    /// ```
    /// use stronghold::Account;
    /// let mnemonic = "gossip region recall forest clip confirm agent grant border spread under lyrics diesel hint mind patch oppose large street panther duty robust city wedding";
    /// let account = Account::import(None, None, mnemonic.to_string(), None).unwrap();
    /// let account_id = account.id();
    /// ```
    pub fn id(&self) -> &[u8; 32] {
        &self.id
    }

    /// Returns the account identifier
    ///
    /// # Example
    /// ```
    /// use stronghold::Account;
    /// let account = Account::new(None).unwrap();
    /// let account_id = account.id();
    /// ```
    pub fn mnemonic(&self) -> &String {
        &self.bip39_mnemonic
    }

    /// Returns the bip39 passphrase of the account
    ///
    /// # Example
    /// ```
    /// use stronghold::Account;
    /// let account = Account::new(Some("banana".to_string())).unwrap();
    /// let account_passphrase = account.passphrase();
    /// ```
    pub fn passphrase(&self) -> &Option<String> {
        &self.bip39_passphrase
    }

    /// Returns the last time the account was updated (timestamp unix epoch)
    ///
    /// # Parameters:
    ///
    /// `update`: If is true, the property will be updated with the current timestamp (and this will be returned)
    ///
    /// # Example
    /// ```
    /// use stronghold::Account;
    /// let mut account = Account::new(Some("banana".to_string())).unwrap();
    /// let last_updated_on = account.last_updated_on(false);
    /// ```
    pub fn last_updated_on(&mut self, update: bool) -> &u128 {
        if update {
            self.last_updated_on = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis()
        };
        &self.last_updated_on
    }
}
