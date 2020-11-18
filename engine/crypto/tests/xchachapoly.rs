// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod common;

use common::{JsonValueExt, ResultExt};
use crypto::XChaChaPoly;
use json::JsonValue;

// vector data.
const VECTORS: &str = include_str!("xchachapoly.json");

// struct for vector data
#[derive(Debug)]
struct TestVector {
    id: String,
    key: Vec<u8>,
    nonce: Vec<u8>,
    ad: Vec<u8>,
    plain: Vec<u8>,
    cipher: Vec<u8>,
}

impl TestVector {
    // load the json vectors
    pub fn load() -> Vec<Self> {
        let json = json::parse(VECTORS).unwrap();
        let mut vecs = Vec::new();

        for vec in json["crypto"].check_array_iter() {
            vecs.push(Self {
                id: vec["id"].check_string(),
                key: vec["key"].check_bytes(),
                nonce: vec["nonce"].check_bytes(),
                ad: vec["ad"].check_bytes(),
                cipher: vec["cipher"].check_bytes(),
                plain: vec["plain"].check_bytes(),
            });
        }

        vecs
    }

    // test encryption
    pub fn test_encryption(&self) -> &Self {
        let mut buf = self.plain.clone();
        buf.extend_from_slice(&[0; 16]);
        XChaChaPoly::aead_cipher()
            .seal(&mut buf, self.plain.len(), &self.ad, &self.key, &self.nonce)
            .unwrap();
        assert_eq!(buf, self.cipher, "Vector: \"{}\"", self.id);

        let mut buf = vec![0; self.cipher.len()];
        XChaChaPoly::aead_cipher()
            .seal_with(&mut buf, &self.plain, &self.ad, &self.key, &self.nonce)
            .unwrap();
        assert_eq!(buf, self.cipher, "Vector: \"{}\"", self.id);

        self
    }

    // test decryption
    pub fn test_decryption(&self) -> &Self {
        let mut buf = self.cipher.clone();
        let len = XChaChaPoly::aead_cipher()
            .open(&mut buf, self.cipher.len(), &self.ad, &self.key, &self.nonce)
            .unwrap();
        assert_eq!(&buf[..len], self.plain.as_slice(), "Vector: \"{}\"", self.id);

        let mut buf = vec![0; self.plain.len()];
        XChaChaPoly::aead_cipher()
            .open_to(&mut buf, &self.cipher, &self.ad, &self.key, &self.nonce)
            .unwrap();
        assert_eq!(buf, self.plain, "Vector: \"{}\"", self.id);

        self
    }
}

#[test]
fn test_crypto() {
    for vec in TestVector::load() {
        vec.test_encryption().test_decryption();
    }
}

// Mac error Vector
#[derive(Debug)]
struct ErrorTestVector {
    id: String,
    key: Vec<u8>,
    nonce: Vec<u8>,
    ad: Vec<u8>,
    cipher: Vec<u8>,
}

impl ErrorTestVector {
    // load json
    pub fn load() -> Vec<Self> {
        let json = json::parse(VECTORS).unwrap();
        let mut vecs = Vec::new();
        for vec in json["error"].check_array_iter() {
            vecs.push(Self {
                id: vec["id"].check_string(),
                key: vec["key"].check_bytes(),
                nonce: vec["nonce"].check_bytes(),
                ad: vec["ad"].check_bytes(),
                cipher: vec["cipher"].check_bytes(),
            });
        }
        vecs
    }

    // test decryption
    pub fn test_decryption(&self) -> &Self {
        let mut buf = self.cipher.clone();
        let error = XChaChaPoly::aead_cipher()
            .open(&mut buf, self.cipher.len(), &self.ad, &self.key, &self.nonce)
            .error_or(format!("Vector: \"{}\"", self.id));
        assert_eq!(error.to_string(), "Invalid Data", "Vector: \"{}\"", self.id);

        let mut buf = vec![0; self.cipher.len()];
        let error = XChaChaPoly::aead_cipher()
            .open_to(&mut buf, &self.cipher, &self.ad, &self.key, &self.nonce)
            .error_or(format!("Vector: \"{}\"", self.id));
        assert_eq!(error.to_string(), "Invalid Data", "Vector: \"{}\"", self.id);

        self
    }
}
#[test]
fn test_error() {
    for vec in ErrorTestVector::load() {
        vec.test_decryption();
    }
}

// API test vector
#[derive(Default, Clone, Debug)]
pub struct ApiTestVector {
    id: String,
    key_len: usize,
    nonce_len: usize,
    ad_len: usize,
    enc_input_len: usize,
    enc_buf_len: usize,
    dec_input_len: usize,
    dec_buf_len: usize,
    error: String,
}
impl ApiTestVector {
    // load json vectors
    pub fn load() -> Vec<Self> {
        let json = json::parse(VECTORS).unwrap();
        let mut defaults = Self::default();
        defaults.load_json(&json["api"]["defaults"]);

        let mut vecs = Vec::new();
        for vec in json["api"]["tests"].members() {
            let mut this = defaults.clone();
            this.load_json(vec);
            vecs.push(this);
        }

        vecs
    }

    // test encryption
    pub fn test_encryption(&self) -> &Self {
        let key = vec![0; self.key_len];
        let nonce = vec![0; self.nonce_len];
        let ad = vec![0; self.ad_len];
        let input = vec![0; self.enc_input_len];
        let mut buf = vec![0; self.enc_buf_len];

        let error = XChaChaPoly::aead_cipher()
            .seal(&mut buf, input.len(), &ad, &key, &nonce)
            .error_or(format!("Vector: \"{}\"", self.id));
        assert_eq!(error.to_string(), self.error, "Vector: \"{}\"", self.id);

        let error = XChaChaPoly::aead_cipher()
            .seal_with(&mut buf, &input, &ad, &key, &nonce)
            .error_or(format!("Vector: \"{}\"", self.id));
        assert_eq!(error.to_string(), self.error, "Vector: \"{}\"", self.id);

        self
    }

    // test decryption
    pub fn test_decryption(&self) -> &Self {
        let key = vec![0; self.key_len];
        let nonce = vec![0; self.nonce_len];
        let ad = vec![0; self.ad_len];
        let input = vec![0; self.dec_input_len];
        let mut buf = vec![0; self.dec_buf_len];

        let error = XChaChaPoly::aead_cipher()
            .open(&mut buf, input.len(), &ad, &key, &nonce)
            .error_or(format!("Vector: \"{}\"", self.id));

        assert_eq!(error.to_string(), self.error, "Vector: \"{}\"", self.id);

        let error = XChaChaPoly::aead_cipher()
            .open_to(&mut buf, &input, &ad, &key, &nonce)
            .error_or(format!("Vector: \"{}\"", self.id));
        assert_eq!(error.to_string(), self.error, "Vector: \"{}\"", self.id);

        self
    }

    // load json
    fn load_json(&mut self, j: &JsonValue) {
        self.id = j["id"].option_string(&self.id);
        self.key_len = j["key_len"].option_usize(self.key_len);
        self.nonce_len = j["nonce_len"].option_usize(self.nonce_len);
        self.ad_len = j["ad_len"].option_usize(self.ad_len);
        self.enc_input_len = j["enc_input_len"].option_usize(self.enc_input_len);
        self.enc_buf_len = j["enc_buf_len"].option_usize(self.enc_buf_len);
        self.dec_input_len = j["dec_input_len"].option_usize(self.dec_input_len);
        self.dec_buf_len = j["dec_buf_len"].option_usize(self.dec_buf_len);
        self.error = j["error"].option_string(&self.error);
    }
}
#[test]
fn test_api() {
    for vec in ApiTestVector::load() {
        vec.test_encryption().test_decryption();
    }
}
