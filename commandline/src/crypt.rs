use crypto::ChaCha20Ietf;
use random::{
    primitives::{cipher::Cipher, rng::SecureRng},
    OsRng,
};

use crate::line_error;

use std::{cell::RefCell, mem};

pub struct CRng {
    key: [u8; 32],
    counter: u64,
}

impl CRng {
    thread_local! {
        static CRNG: RefCell<CRng> = RefCell::new({
            let mut key = [0; 32];
            OsRng.random(&mut key).expect("Fialed to generate random seed");
            CRng {
                key, counter: 0
            }
        });

    }

    pub fn random(buf: &mut [u8]) {
        Self::CRNG.with(|crng| {
            let mut crng = crng.borrow_mut();
            buf.iter_mut().for_each(|b| *b = 0);

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
}
