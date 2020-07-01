use crate::keys::public::{ActionSignature, KeyAction, PublicKey};

use crate::utils::{calc_hash, concat};

use serde::{Deserialize, Serialize};

use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    io::Read,
};

#[derive(Serialize, Deserialize, Clone)]
pub struct KeyStore {
    pub internal: Vec<StoreInternals>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StoreInternals {
    pub parent: Vec<u8>,
    pub action: KeyAction,
    pub signature: ActionSignature,
}

impl KeyStore {
    pub fn new() -> Self {
        KeyStore {
            internal: Vec::new(),
        }
    }

    pub fn read_store() -> crate::Result<KeyStore> {
        let store_file = crate::files::keystore_file()?;
        let contents = fs::read_to_string(store_file)?;

        Ok(serde_json::from_str(&contents)?)
    }

    pub fn write_store(&self) -> crate::Result<()> {
        let store_file = crate::files::keystore_file()?;
        let bytes = serde_json::to_string(self)?;

        Ok(fs::write(store_file, bytes.as_bytes())?)
    }

    pub fn check_id(&self, id: &str) -> bool {
        let mut valid = HashSet::new();

        for it in self.internal.iter() {
            match &it.action {
                KeyAction::New(kw) => valid.insert(kw.id.to_string()),
                KeyAction::Sign(kw) => valid.insert(kw.id.to_string()),
                KeyAction::Revoke(kw) => valid.remove(&kw.id),
            };
        }

        valid.contains(id)
    }

    pub fn is_empty(&self) -> bool {
        self.internal.is_empty()
    }

    pub fn get_digest(&self) -> Vec<u8> {
        if self.is_empty() {
            return Vec::new();
        }
        self.internal[self.internal.len() - 1].get_digest()
    }

    pub fn get_verified_keys(&self) -> Option<HashMap<String, &PublicKey>> {
        let head = get_head().ok()?;

        self.verify(head.clone(), false)
    }

    pub fn verify_merge(&self) -> bool {
        let head = get_head().expect("Unable to get head file");

        let res = self.verify(head.clone(), true);

        let new_head = self.get_digest();
        if new_head != head {
            write_head_file(&new_head).unwrap();
        }

        res.is_some()
    }

    pub fn verify(&self, head: Vec<u8>, is_merge: bool) -> Option<HashMap<String, &PublicKey>> {
        if self.is_empty() {
            return None;
        }

        if !is_merge && head != self.get_digest() {
            return None;
        }

        let mut trusted: HashMap<String, &PublicKey> = HashMap::new();
        let mut is_trusted = false;
        let mut parent_digest: Option<Vec<u8>> = None;
        let store_len = self.internal.len();

        for (idx, it) in self.internal.iter().enumerate() {
            if idx != 0 {
                if let None = parent_digest {
                    return None;
                };

                if &it.parent != parent_digest.as_ref().unwrap() {
                    return None;
                }
            }

            let it_digest = it.get_digest();
            parent_digest = Some(it_digest.clone());

            match &it.action {
                KeyAction::New(kw) => {
                    let mut sign_key = trusted.get(&it.signature.id);
                    if idx != 0 {
                        if let None = sign_key {
                            return None;
                        } else {
                            trusted.insert(kw.id.clone(), &kw.key);
                            sign_key = trusted.get(&kw.id);
                        }

                        let expected_payload = it.signature_payload();
                        if !sign_key
                            .unwrap()
                            .verify(&it.signature.payload, &expected_payload)
                        {
                            return None;
                        }
                        trusted.insert(kw.id.clone(), &kw.key);
                    }
                }
                KeyAction::Sign(kw) => {
                    if !is_merge {
                        return None;
                    }

                    let expected_payload =
                        calc_hash(&concat(&[&it.parent, &it.action.get_digest()]));

                    if !kw.key.verify(&it.signature.payload, &expected_payload) {
                        return None;
                    }

                    if idx != store_len - 1 {
                        return None;
                    }
                }
                KeyAction::Revoke(kw) => {
                    let sign_key = trusted.get(&it.signature.id);
                    if let None = sign_key {
                        return None;
                    };

                    let expected_payload =
                        calc_hash(&concat(&[&it.parent, &it.action.get_digest()]));

                    if !sign_key
                        .unwrap()
                        .verify(&it.signature.payload, &expected_payload)
                    {
                        return None;
                    }
                    trusted.remove(&kw.id);
                }
            }

            if it_digest == head {
                is_trusted = true;
            }
        }

        if !is_trusted {
            None
        } else {
            Some(trusted)
        }
    }
}

impl StoreInternals {
    pub fn get_digest(&self) -> Vec<u8> {
        calc_hash(&concat(&[
            &self.parent,
            &self.action.get_digest(),
            &self.signature.get_digest(),
        ]))
    }

    pub fn signature_payload(&self) -> Vec<u8> {
        calc_hash(&concat(&[&self.parent, &self.action.get_digest()]))
    }
}

pub fn write_head_file(head: &[u8]) -> crate::Result<()> {
    let file = crate::files::keystore_head()?;
    let contents = serde_json::to_string(head)?;
    let res = fs::write(file, contents.as_bytes())?;

    Ok(())
}

fn get_head() -> crate::Result<Vec<u8>> {
    let head_file = crate::files::keystore_head()?;
    let mut contents = String::new();
    let mut head_file = File::open(head_file)?;
    head_file.read_to_string(&mut contents)?;

    Ok(serde_json::from_str(&contents)?)
}
