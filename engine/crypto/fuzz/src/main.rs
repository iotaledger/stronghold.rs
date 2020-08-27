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

use crypto::{primitives::cipher::AeadCipher, ChaChaPolyIetf, XChaChaPoly};
use hex::ToHex;
use sodiumoxide::crypto::{
    aead::{chacha20poly1305_ietf, xchacha20poly1305_ietf},
    stream::salsa20,
};

use std::{
    env,
    ops::Range,
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering::Relaxed},
    thread,
    time::Duration,
};

// atomic counter for the tests.
static COUNTER: AtomicU64 = AtomicU64::new(0);

// a rng using salsa20.
struct SecureRng {
    seed: salsa20::Key,
    ctr: u64,
}

// ChaChaPolyIetf Test Vector.
struct ChaChaPolyVector {
    key: Vec<u8>,
    nonce: Vec<u8>,
    plain: Vec<u8>,
    ad: Vec<u8>,
}
// XChaChaPolyIetf Test Vector.
struct XChaChaPolyVector {
    key: Vec<u8>,
    nonce: Vec<u8>,
    plain: Vec<u8>,
    ad: Vec<u8>,
}

impl SecureRng {
    // create a new SecureRNG
    pub fn new() -> Self {
        Self {
            seed: salsa20::gen_key(),
            ctr: 0,
        }
    }

    // generate random bytes and fill the buffer with them.
    pub fn random(&mut self, buf: &mut [u8]) {
        // create nonce.
        let nonce = salsa20::Nonce::from_slice(&self.ctr.to_be_bytes()).unwrap();
        self.ctr += 1;
        // create random bytes.
        buf.iter_mut().for_each(|b| *b = 0);
        salsa20::stream_xor_inplace(buf, &nonce, &self.seed);
    }

    // create a vector filled with random bytes based on a length.
    pub fn random_vec(&mut self, len: usize) -> Vec<u8> {
        let mut buf = vec![0; len];
        self.random(&mut buf);
        buf
    }

    // generate a random number within a range.
    pub fn random_range(&mut self, range: Range<u128>) -> u128 {
        // Calculate bucket size and amount.
        let bucket_size = range.end - range.start;
        let bucket_count = u128::max_value() / bucket_size;

        // Calculate the Random Number.
        let mut num = [0; 16];
        loop {
            self.random(&mut num);
            let num = u128::from_ne_bytes(num);

            // check if number is in the range.
            if num < bucket_size * bucket_count {
                return (num % bucket_size) + range.start;
            }
        }
    }

    // Generates a vector of random length filled with random data based on a range.
    pub fn random_len_vec(&mut self, range: Range<usize>) -> Vec<u8> {
        let range = (range.start as u128)..(range.end as u128);
        let len = self.random_range(range) as usize;
        self.random_vec(len)
    }
}

impl ChaChaPolyTestVector {
    // generate a random test vector.
    pub fn random(limit: usize, rng: &mut SecureRng) -> Self {
        Self {
            key: rng.random_vec(32),
            nonce: rng.random_vec(12),
            plain: rng.random_len_vec(0..limit),
            ad: rng.random_len_vec(0..limit),
        }
    }

    // test the test vector.
    pub fn test(self) {
        // seal the data using ChaChaPolyIETF
        let mut ct_crypto = vec![0u8; self.plain.len() + 16];
        ChaChaPolyIetf
            .seal_with(
                &mut ct_crypto,
                &self.plain,
                &self.ad,
                self.key.as_ref(),
                self.nonce.as_ref(),
            )
            .unwrap();

        // Seal the data with Sodiumoxide
        let ct_sodium = chacha20poly1305_ietf::seal(
            &self.plain,
            if self.ad.len() > 0 {
                Some(&self.ad)
            } else {
                None
            },
            &chacha20poly1305_ietf::Nonce::from_slice(&self.nonce).unwrap(),
            &chacha20poly1305_ietf::Key::from_slice(&self.key).unwrap(),
        );

        // Compare the sealed data.
        if ct_crypto != ct_sodium {
            eprintln!("Error Report:");
            eprintln!("Key: {}", self.key.encode_hex::<String>());
            eprintln!("Nonce: {}", self.nonce.encode_hex::<String>());
            eprintln!("Plain: {}", self.plain.encode_hex::<String>());
            eprintln!("AD: {}", self.ad.encode_hex::<String>());
            eprintln!("Outputs:");
            eprintln!("Crypto: {}", ct_crypto.encode_hex::<String>());
            eprintln!("Sodiumoxide: {}", ct_sodium.encode_hex::<String>());
            panic!("Exiting. Please save this error information.");
        }
        // increment the counter.
        COUNTER.fetch_add(1, Relaxed);
    }
}

impl XChaChaPolyTestVector {
    // generate a random test vector.
    pub fn random(limit: usize, rng: &mut SecureRng) -> Self {
        Self {
            key: rng.random_vec(32),
            nonce: rng.random_vec(24),
            plain: rng.random_len_vec(0..limit),
            ad: rng.random_len_vec(0..limit),
        }
    }

    pub fn test(self) {
        // seal the data using XChaChaPoly
        let mut ct_crypto = vec![0u8; self.plain.len() + 16];
        XChaChaPoly
            .seal_with(
                &mut ct_crypto,
                &self.plain,
                &self.ad,
                self.key.as_ref(),
                self.nonce.as_ref(),
            )
            .unwrap();

        // Seal the data with Sodiumoxide
        let ct_sodium = xchacha20poly1305_ietf::seal(
            &self.plain,
            if self.ad.len() > 0 {
                Some(&self.ad)
            } else {
                None
            },
            &xchacha20poly1305_ietf::Nonce::from_slice(&self.nonce).unwrap(),
            &xchacha20poly1305_ietf::Key::from_slice(&self.key).unwrap(),
        );

        // Compare the sealed data.
        if ct_crypto != ct_sodium {
            eprintln!("Error Report:");
            eprintln!("Key: {}", self.key.encode_hex::<String>());
            eprintln!("Nonce: {}", self.nonce.encode_hex::<String>());
            eprintln!("Plain: {}", self.plain.encode_hex::<String>());
            eprintln!("AD: {}", self.ad.encode_hex::<String>());
            eprintln!("Outputs:");
            eprintln!("Crypto: {}", ct_crypto.encode_hex::<String>());
            eprintln!("Sodiumoxide: {}", ct_sodium.encode_hex::<String>());
            panic!("Exiting. Please save this error information.");
        }
        // increment the counter.
        COUNTER.fetch_add(1, Relaxed);
    }
}

fn main() {
    // get the threads from the THREADS enviroment var.
    let threads_str = env::var("NUM_THREADS").unwrap_or(num_cpus::get().to_string());
    let threads = usize::from_str(&threads_str).expect("Invalid value of THREADS");

    // load the enviroment limit from the VECTOR_LIMIT env var.
    let limit_str = env::var("VECTOR_LIMIT").unwrap_or(264.to_string());
    let limit = usize::from_str(&limit_str).expect("Invalid value of TEST_VECTOR_LIMIT");

    // fuzz the threads.
    for _ in 0..threads {
        let mut rng = SecureRng::new();
        thread::spawn(move || loop {
            ChaChaPolyVector::random(limit, &mut rng).test();
            XChaChaPolyVector::random(limit, &mut rng).test()
        });
    }

    // Show the progress of fuzzing.
    println!(
        "Spraying Fuzz [Num Of Threads = {}, Vector Limit = {} bytes]...",
        threads, limit
    );
    loop {
        thread::sleep(Duration::from_secs(5));
        println!("Performed {} tests...", COUNTER.load(Relaxed));
    }
}
