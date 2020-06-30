use crate::utils::{calc_hash, concat};

use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::{box_, sealedbox, sign};

#[derive(Serialize, Deserialize, Clone)]
pub struct PublicKey {
    pub encrypt: box_::PublicKey,
    pub sign: sign::PublicKey,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PublicWrapper {
    pub id: String,
    pub key: PublicKey,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum KeyAction {
    New(PublicWrapper),
    SignRequest(PublicWrapper),
    Revoke(PublicWrapper),
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ActionSignature {
    pub key_id: String,
    pub payload: Vec<u8>,
}

impl PublicKey {
    fn get_digest(&self) -> Vec<u8> {
        let bytes = concat(&[&self.encrypt.0, &self.sign.0]);
        calc_hash(&bytes)
    }

    fn verify(&self, payload: &[u8], expected: &[u8]) -> bool {
        let sig = sign::Signature::from_slice(payload);
        if let None = sig {
            return false;
        };

        let sig = sig.unwrap();

        sign::verify_detached(&sig, expected, &self.sign)
    }

    fn encrypt(&self, payload: &[u8]) -> Vec<u8> {
        sealedbox::seal(payload, &self.encrypt)
    }
}

impl PublicWrapper {
    pub fn get_digest(&self) -> Vec<u8> {
        calc_hash(&concat(&[self.id.as_bytes(), &self.key.get_digest()]))
    }

    pub fn verify(&self, payload: &[u8], expected: &[u8]) -> bool {
        self.key.verify(payload, expected)
    }

    pub fn encrypt(&self, payload: &[u8]) -> Vec<u8> {
        self.key.encrypt(payload)
    }
}

impl KeyAction {
    pub fn get_digest(&self) -> Vec<u8> {
        match self {
            KeyAction::New(kw) => calc_hash(&concat(&["new".as_bytes(), &kw.get_digest()])),
            KeyAction::SignRequest(kw) => {
                calc_hash(&concat(&["sign".as_bytes(), &kw.get_digest()]))
            }
            KeyAction::Revoke(kw) => calc_hash(&concat(&["revoke".as_bytes(), &kw.get_digest()])),
        }
    }
}

impl ActionSignature {
    fn get_digest(&self) -> Vec<u8> {
        calc_hash(&concat(&[self.key_id.as_bytes(), &self.payload]))
    }
}
