use crypto::{chachapoly::ChachaPolyIetf, primitives::cipher::AeadCipher};
use hex::ToHex;
use sodiumoxide::crypto::{aead::chacha20poly1305_ietf, stream::salsa20};

use std::{
    env,
    ops::Range,
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering::Relaxed},
    thread,
    time::Duration,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct SecureRng {
    seed: salsa20::Key,
    ctr: u64,
}

impl SecureRng {
    pub fn new() -> Self {
        Self {
            seed: salsa20::gen_key(),
            ctr: 0,
        }
    }

    pub fn random(&mut self, buf: &mut [u8]) {
        let nonce = salsa20::Nonce::from_slice(&self.ctr.to_be_bytes()).unwrap();
        self.ctr += 1;

        buf.iter_mut().for_each(|b| *b = 0);
        salsa20::stream_xor_inplace(buf, &nonce, &self.seed);
    }
    pub fn random_vec(&mut self, len: usize) -> Vec<u8> {
        let mut buf = vec![0; len];
        self.random(&mut buf);
        buf
    }
    pub fn random_range(&mut self, range: Range<u128>) -> u128 {
        let bucket_size = range.end - range.start;
        let bucket_count = u128::max_value() / bucket_size;

        let mut num = [0; 16];
        loop {
            self.random(&mut num);
            let num = u128::from_ne_bytes(num);

            if num < bucket_size * bucket_count {
                return (num % bucket_size) + range.start;
            }
        }
    }
    pub fn random_len_vec(&mut self, range: Range<usize>) -> Vec<u8> {
        let range = (range.start as u128)..(range.end as u128);
        let len = self.random_range(range) as usize;
        self.random_vec(len)
    }
}

struct ChaChaPolyTestVector {
    key: Vec<u8>,
    nonce: Vec<u8>,
    plain: Vec<u8>,
    ad: Vec<u8>,
}

impl ChaChaPolyTestVector {
    pub fn random(limit: usize, rng: &mut SecureRng) -> Self {
        Self {
            key: rng.random_vec(32),
            nonce: rng.random_vec(12),
            plain: rng.random_len_vec(0..limit),
            ad: rng.random_len_vec(0..limit),
        }
    }

    pub fn test(self) {
        let mut ct_crypto = vec![0u8; self.plain.len() + 16];
        ChachaPolyIetf
            .seal_to(
                &mut ct_crypto,
                &self.plain,
                &self.ad,
                self.key.as_ref(),
                self.nonce.as_ref(),
            )
            .unwrap();

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

        if ct_crypto != ct_sodium {
            eprintln!("Mismatch!. Inputs:");
            eprintln!("Key: {}", self.key.encode_hex::<String>());
            eprintln!("Nonce: {}", self.nonce.encode_hex::<String>());
            eprintln!("Plain: {}", self.plain.encode_hex::<String>());
            eprintln!("Additional data: {}", self.ad.encode_hex::<String>());
            eprintln!("Outputs:");
            eprintln!("Crypto: {}", ct_crypto.encode_hex::<String>());
            eprintln!("Libsodium: {}", ct_sodium.encode_hex::<String>());
            panic!("... aborting. Please save and report this error!");
        }
        COUNTER.fetch_add(1, Relaxed);
    }
}

fn main() {
    let threads_str = env::var("THREADS").unwrap_or(num_cpus::get().to_string());
    let threads = usize::from_str(&threads_str).expect("Invalid value of THREADS");

    let limit_str = env::var("VECTOR_LIMIT").unwrap_or(264.to_string());
    let limit = usize::from_str(&limit_str).expect("Invalid value of TEST_VECTOR_LIMIT");

    for _ in 0..threads {
        let mut rng = SecureRng::new();
        thread::spawn(move || loop {
            ChaChaPolyTestVector::random(limit, &mut rng).test();
        });
    }

    println!(
        "Starting fuzzing [THREADS = {}, TEST_VECTOR_LIMIT = {} bytes]...",
        threads, limit
    );
    loop {
        thread::sleep(Duration::from_secs(5));
        println!("Performed {} tests...", COUNTER.load(Relaxed));
    }
}
