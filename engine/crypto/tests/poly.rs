mod common;

use common::{JsonValueExt, ResultExt};
use crypto::Poly1305;
use json::JsonValue;

// vector data.
const VECTORS: &str = include_str!("poly.json");

// struct for vector data
#[derive(Debug)]
struct TestVector {
    id: String,
    key: Vec<u8>,
    data: Vec<u8>,
    mac: Vec<u8>,
}

impl TestVector {
    // load json vectors
    pub fn load() -> Vec<Self> {
        let json = json::parse(VECTORS).unwrap();
        let mut vecs = Vec::new();
        for vec in json["crypto"].check_array_iter() {
            vecs.push(Self {
                id: vec["id"].check_string(),
                key: vec["key"].check_bytes(),
                data: vec["data"].check_bytes(),
                mac: vec["mac"].check_bytes(),
            });
        }
        vecs
    }

    // test mac calculation
    pub fn test_mac(&self) -> &Self {
        let mut buf = vec![0; self.mac.len()];
        Poly1305::message_auth_code()
            .auth(&mut buf, &self.data, &self.key)
            .unwrap();
        assert_eq!(buf, self.mac, "Vector: \"{}\"", self.id);

        self
    }
}

#[test]
fn test_crypto() {
    for vec in TestVector::load() {
        vec.test_mac();
    }
}

// API test vector
#[derive(Default, Clone, Debug)]
pub struct ApiTestVector {
    id: String,
    key_len: usize,
    data_len: usize,
    buf_len: usize,
    error: String,
}

impl ApiTestVector {
    // load json
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

    /// Tests the MAC Calculation
    pub fn test_mac(&self) -> &Self {
        let key = vec![0; self.key_len];
        let data = vec![0; self.data_len];
        let mut buf = vec![0; self.buf_len];

        let error = Poly1305::message_auth_code()
            .auth(&mut buf, &data, &key)
            .error_or(format!("Vector: \"{}\"", self.id));
        assert_eq!(error.to_string(), self.error, "Vector: \"{}\"", self.id);

        self
    }

    // load json
    fn load_json(&mut self, j: &JsonValue) {
        self.id = j["id"].option_string(&self.id);
        self.key_len = j["key_len"].option_usize(self.key_len);
        self.data_len = j["data_len"].option_usize(self.data_len);
        self.buf_len = j["buf_len"].option_usize(self.buf_len);
        self.error = j["error"].option_string(&self.error);
    }
}
#[test]
fn test_api() {
    for vec in ApiTestVector::load() {
        vec.test_mac();
    }
}
