pub use primitives;
use primitives::rng::SecureRng;
use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
};

/// Rust Bindings to major C random generator headers.  A library that creates secure random number generators.
///
/// This crate implements the RNG (random number generator) traits defined in the primitives crate to describe a secure
/// random number generator. C code was used when creating this crate because all of the major platforms feature battle
/// tested RNG libraries. This C code is bridged with Rust using CC and Rust’s FFI (foreign function
/// interface). This crate supports windows, mac, linux, iOS and a few BSD flavors.

/// Error for dealing with errors from the OS RNG.
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct OsRandomErr;
impl Display for OsRandomErr {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{:?}", self)
    }
}
impl Error for OsRandomErr {}

/// an interface for the OS's secure RNG
pub struct OsRng;
impl OsRng {
    pub fn secure_rng() -> Box<dyn SecureRng> {
        Box::new(Self)
    }
}

impl SecureRng for OsRng {
    /// fill the `buf` with random bytes.
    fn random(&mut self, buf: &mut [u8]) -> Result<(), Box<dyn Error + 'static>> {
        // the API bridge
        extern "C" {
            fn os_random_secrandom(buf: *mut u8, len: usize) -> u8;
        }

        // call to the c code
        match unsafe { os_random_secrandom(buf.as_mut_ptr(), buf.len()) } {
            0 => Ok(()),
            _ => Err(OsRandomErr.into()),
        }
    }
}

#[cfg(test)]
mod test {
    use super::OsRng;

    const TEST_SIZES: &[usize] = &[1024 * 1024, 4 * 1024 * 1024, (4 * 1024 * 1024) + 15];
    const ITERATIONS: usize = 8;

    /// test the uniform distribution of byte values.
    fn test_uniform_dist(buf: &[u8]) {
        let mut dist = vec![0f64; 256];
        buf.iter().for_each(|b| dist[*b as usize] += 1.0);

        let estimated_avg = (buf.len() as f64) / 256.0;
        let (estimated_min, estimated_max) = (estimated_avg * 0.9, estimated_avg * 1.1);
        dist.iter().for_each(|d| {
            assert!(*d > estimated_min, "{} is not > {}", *d, estimated_min);
            assert!(*d < estimated_max, "{} is not < {}", *d, estimated_max);
        });
    }

    #[test]
    fn test() {
        for _ in 0..ITERATIONS {
            for size in TEST_SIZES.iter() {
                let mut buf = vec![0; *size];
                OsRng::secure_rng().random(&mut buf).unwrap();
                test_uniform_dist(&buf)
            }
        }
    }

    #[test]
    #[should_panic]
    fn testing_uniform_dist() {
        test_uniform_dist(&[0; (4 * 1024 * 1024) + 15])
    }
}
