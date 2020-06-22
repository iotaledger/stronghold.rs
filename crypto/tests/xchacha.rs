mod common;

use common::{JsonValueExt, ResultExt};
use crypto::XChaCha20;
use json::JsonValue;

const VECTORS: &str = include_str!("xchacha.json");

#[derive(Debug)]
struct TestVector {
    id: String,
    key: Vec<u8>,
    nonce: Vec<u8>,
    cipher: Vec<u8>,
}

impl TestVector {
    pub fn load() -> Vec<Self> {
        let json = json::parse(VECTORS).unwrap();
        let mut vecs = Vec::new();

        for vec in json["crypto"].check_array_iter() {
            vecs.push(Self {
                id: vec["id"].check_string(),
                key: vec["key"].check_bytes(),
                nonce: vec["nonce"].check_bytes(),
                cipher: vec["cipher"].check_bytes(),
            });
        }

        vecs
    }

    pub fn test_keystream_encryption(&self) -> &Self {
        let mut buf = vec![0; self.cipher.len()];
        XChaCha20::cipher()
            .encrypt(&mut buf, self.cipher.len(), &self.key, &self.nonce)
            .unwrap();
        assert_eq!(buf, self.cipher, "Vector: \"{}\"", self.id);

        self
    }
    pub fn test_keystream_decryption(&self) -> &Self {
        let mut buf = vec![0; self.cipher.len()];
        XChaCha20::cipher()
            .decrypt(&mut buf, self.cipher.len(), &self.key, &self.nonce)
            .unwrap();
        assert_eq!(buf, self.cipher, "Test vector: \"{}\"", self.id);

        self
    }
}

#[test]
fn test_crypto() {
    for vec in TestVector::load() {
        vec.test_keystream_encryption().test_keystream_decryption();
    }
}

#[derive(Default, Clone, Debug)]
pub struct ApiTestVector {
    id: String,
    key_len: usize,
    nonce_len: usize,
    enc_input_len: usize,
    enc_buf_len: usize,
    dec_input_len: usize,
    dec_buf_len: usize,
    error: String,
}
impl ApiTestVector {
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

    pub fn test_encryption(&self) -> &Self {
        let key = vec![0; self.key_len];
        let nonce = vec![0; self.nonce_len];
        let input = vec![0; self.enc_input_len];
        let mut buf = vec![0; self.enc_buf_len];

        let error = XChaCha20::cipher()
            .encrypt(&mut buf, input.len(), &key, &nonce)
            .error_or(format!("Vector: \"{}\"", self.id));
        assert_eq!(error.to_string(), self.error, "Vector: \"{}\"", self.id);

        let error = XChaCha20::cipher()
            .encrypt_to(&mut buf, &input, &key, &nonce)
            .error_or(format!("Vector: \"{}\"", self.id));
        assert_eq!(error.to_string(), self.error, "Vector: \"{}\"", self.id);

        self
    }

    pub fn test_decryption(&self) -> &Self {
        let key = vec![0; self.key_len];
        let nonce = vec![0; self.nonce_len];
        let input = vec![0; self.dec_input_len];
        let mut buf = vec![0; self.dec_buf_len];

        let error = XChaCha20::cipher()
            .decrypt(&mut buf, input.len(), &key, &nonce)
            .error_or(format!("Vector: \"{}\"", self.id));
        assert_eq!(error.to_string(), self.error, "Vector: \"{}\"", self.id);

        let error = XChaCha20::cipher()
            .decrypt_to(&mut buf, &input, &key, &nonce)
            .error_or(format!("Vector: \"{}\"", self.id));
        assert_eq!(error.to_string(), self.error, "Vector: \"{}\"", self.id);

        self
    }

    fn load_json(&mut self, j: &JsonValue) {
        self.id = j["id"].option_string(&self.id);
        self.key_len = j["key_len"].option_usize(self.key_len);
        self.nonce_len = j["nonce_len"].option_usize(self.nonce_len);
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
