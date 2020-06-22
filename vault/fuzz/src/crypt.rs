use vault::{BoxProvider, Error, Key};

use primitives::{
    cipher::{AeadCipher, Cipher},
    rng::SecureRng,
};
use random::OsRng;

use crypto::{chacha_ietf::ChaCha20Ietf, xchachapoly::XChaChaPoly};

use std::{cell::RefCell, mem};

pub struct CRng {
    key: [u8; 32],
    counter: u64,
}

impl CRng {
    thread_local! {
        static CRng: RefCell<CRng> = RefCell::new({
            let mut key = [0; 32];
            OsRng.random(&mut key).expect("Failed to generate seed");
            CRng {
                key, counter: 0
            }
        });
    }

    pub fn random(buf: &mut [u8]) {
        Self::CRng.with(|crng| {
            let mut crng = crng.borrow_mut();
            buf.iter_mut().for_each(|x| *x = 0);

            let mut nonce = [0; 12];
            nonce[4..].copy_from_slice(&crng.counter.to_be_bytes());
            crng.counter += 1;

            ChaCha20Ietf
                .encrypt(buf, buf.len(), &crng.key, &nonce)
                .expect(line_error!());
        });
    }

    pub fn random_vec(len: usize) -> Vec<u8> {
        let mut buf = vec![0; len];
        Self::random(&mut buf);
        buf
    }

    pub fn usize(limit: usize) -> usize {
        let bucket_size = limit;
        let bucket_count = usize::max_value() / bucket_size;

        let mut num = [0; mem::size_of::<usize>()];
        loop {
            Self::random(&mut num);
            let num = usize::from_ne_bytes(num);

            if num < bucket_size * bucket_count {
                return num % bucket_size;
            }
        }
    }

    pub fn bool(n: usize) -> bool {
        Self::usize(n) == 0
    }

    pub fn payload() -> Vec<u8> {
        const LIMIT: usize = 16_384;
        let len = Self::usize(LIMIT);
        Self::random_vec(len)
    }
}

pub struct Provider;

impl Provider {
    const NONCE: usize = 24;
    const TAG: usize = 16;
}

impl BoxProvider for Provider {
    fn box_key_len() -> usize {
        32
    }
    fn box_overhead() -> usize {
        Self::NONCE + Self::TAG
    }

    fn box_seal(key: &Key<Self>, ad: &[u8], plaintext: &[u8]) -> vault::Result<Vec<u8>> {
        let mut r#box = vec![0; plaintext.len() + Self::box_overhead()];
        let (nonce, ciphertext) = r#box.split_at_mut(Self::NONCE);
        CRng::random(nonce);

        XChaChaPoly
            .seal_with(ciphertext, plaintext, ad, key.bytes(), nonce)
            .map_err(|e| vault::Error::OtherError(String::from("failed to seal")))?;
        Ok(r#box)
    }

    fn box_open(key: &Key<Self>, ad: &[u8], r#box: &[u8]) -> vault::Result<Vec<u8>> {
        let mut plaintext = match r#box.len() {
            len if len >= Self::box_overhead() => vec![0; len - Self::box_overhead()],
            _ => Err(Error::ChainError(String::from("Truncated ciphertext")))?,
        };
        let (nonce, ciphertext) = r#box.split_at(Self::NONCE);

        XChaChaPoly
            .open_to(&mut plaintext, ciphertext, ad, key.bytes(), nonce)
            .map_err(|_| Error::ChainError(String::from("Invalid ciphertext")))?;
        Ok(plaintext)
    }
    fn random_buf(buf: &mut [u8]) -> vault::Result<()> {
        Ok(CRng::random(buf))
    }
}
