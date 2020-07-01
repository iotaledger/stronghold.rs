use serde::{Deserialize, Serialize};

use glob::glob;
use sodiumoxide::crypto::{
    box_, pwhash, pwhash::Salt, sealedbox, secretbox, secretbox::Nonce, sign,
};

use std::fs;

#[derive(Serialize, Deserialize)]
pub enum PrivateKey {
    Encrypted(EncryptedPrivateKey),
    Unencrypted(UnencryptedPrivateKey),
}

#[derive(Serialize, Deserialize, Clone)]
pub struct UnencryptedPrivateKey {
    pub encrypt_key: box_::SecretKey,
    pub sign_key: sign::SecretKey,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedPrivateKey {
    encrypt_salt: Salt,
    encrypt_nonce: Nonce,
    encrypt_key: Vec<u8>,
    sign_salt: Salt,
    sign_nonce: Nonce,
    sign_key: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct PrivateWrapper {
    pub id: String,
    pub key: PrivateKey,
}

impl PrivateKey {
    pub fn sign(&self, msg: &[u8]) -> crate::Result<Vec<u8>> {
        match self {
            PrivateKey::Unencrypted(key) => Ok(sign::sign_detached(msg, &key.sign_key).0.to_vec()),
            PrivateKey::Encrypted(_) => {
                Err(crate::Error::CryptoError("Can't sign with this key".into()))
            }
        }
    }

    pub fn decrypt(&self, cipher: &[u8]) -> crate::Result<Vec<u8>> {
        match self {
            PrivateKey::Unencrypted(key) => {
                let pub_key = key.encrypt_key.public_key();
                let plain = sealedbox::open(cipher, &pub_key, &key.encrypt_key);
                Ok(plain.unwrap())
            }
            PrivateKey::Encrypted(_) => Err(crate::Error::CryptoError(
                "Can't decrypt the message with this key".into(),
            )),
        }
    }
}

impl EncryptedPrivateKey {
    fn new(
        pass: &str,
        encrypt_key: box_::SecretKey,
        sign_key: sign::SecretKey,
    ) -> EncryptedPrivateKey {
        let encrypt_salt = pwhash::gen_salt();
        let encrypt_nonce = secretbox::gen_nonce();
        let mut ekey = [0; secretbox::KEYBYTES];
        pwhash::derive_key_interactive(&mut ekey, pass.as_bytes(), &encrypt_salt).unwrap();
        let ekey = secretbox::Key::from_slice(&ekey).unwrap();
        let encrypt_ekey = secretbox::seal(&encrypt_key.0, &encrypt_nonce, &ekey);

        let sign_salt = pwhash::gen_salt();
        let sign_nonce = secretbox::gen_nonce();
        let mut skey = [0; secretbox::KEYBYTES];
        pwhash::derive_key_interactive(&mut skey, pass.as_bytes(), &sign_salt).unwrap();
        let skey = secretbox::Key::from_slice(&skey).unwrap();
        let encrypt_skey = secretbox::seal(&sign_key.0, &sign_nonce, &skey);

        EncryptedPrivateKey {
            encrypt_salt,
            encrypt_nonce,
            encrypt_key: encrypt_ekey,
            sign_salt,
            sign_nonce,
            sign_key: encrypt_skey,
        }
    }

    pub fn decrypt_key(&self, pass: &str) -> Option<UnencryptedPrivateKey> {
        let encrypt_key = decrypt_key_param(
            &self.encrypt_key,
            pass,
            &self.encrypt_salt,
            &self.encrypt_nonce,
        )?;

        let sign_key = decrypt_key_param(&self.sign_key, pass, &self.sign_salt, &self.sign_nonce)?;

        Some(UnencryptedPrivateKey {
            encrypt_key: box_::SecretKey::from_slice(&encrypt_key)?,
            sign_key: sign::SecretKey::from_slice(&sign_key)?,
        })
    }
}

fn decrypt_key_param(payload: &[u8], pass: &str, salt: &Salt, nonce: &Nonce) -> Option<Vec<u8>> {
    let mut symmetric_key = [0; secretbox::KEYBYTES];
    pwhash::derive_key_interactive(&mut symmetric_key, pass.as_bytes(), salt).unwrap();
    let symmetric_key = secretbox::Key::from_slice(&symmetric_key).unwrap();
    secretbox::open(payload, nonce, &symmetric_key).ok()
}

pub fn get_keys_from_device() -> crate::Result<Vec<PrivateWrapper>> {
    let key_dir = crate::files::key_dir()?;
    let glob_path = key_dir.join("*.encrypt");
    let mut keys = Vec::new();

    let key_glob = glob(glob_path.to_str().unwrap());

    if let Err(_) = key_glob {
        return Ok(keys);
    };

    let key_glob = key_glob?;

    for path in key_glob {
        if let Err(_) = path {
            continue;
        };

        let key_path = path.unwrap();
        let contents = fs::read_to_string(key_path)?;
        let sec_key = serde_json::from_str(&contents)?;
        keys.push(sec_key);
    }

    Ok(keys)
}

pub fn write_private_key(
    id: &str,
    pass: &str,
    enc_key: box_::SecretKey,
    sign_key: sign::SecretKey,
) -> crate::Result<()> {
    let key = if pass.is_empty() {
        PrivateKey::Unencrypted(UnencryptedPrivateKey {
            encrypt_key: enc_key,
            sign_key,
        })
    } else {
        PrivateKey::Encrypted(EncryptedPrivateKey::new(&pass, enc_key, sign_key))
    };

    let key_wrapper = PrivateWrapper {
        id: id.to_string(),
        key: key,
    };

    let key_bytes = serde_json::to_string(&key_wrapper)?;
    let key_path = crate::files::key_dir()?.join(format!("{}.encrypt", id));

    Ok(fs::write(key_path, &key_bytes)?)
}
