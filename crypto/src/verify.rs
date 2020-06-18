pub trait USizeExt {
    fn constrain_value(&self) -> usize;
}

pub trait SliceExt {
    fn constrain_value(&self) -> usize;
}

impl USizeExt for usize {
    fn constrain_value(&self) -> usize {
        *self
    }
}

impl<T: AsRef<[u8]>> SliceExt for T {
    fn constrain_value(&self) -> usize {
        self.as_ref().len()
    }
}

#[macro_export]
macro_rules! verify_keygen {
    ($size:expr => $buf:expr) => {{
        #[allow(unused_imports)]
        use $crate::verify::{SliceExt, USizeExt};

        let error = match true {
            _ if $buf.constrain_value() != $size => Err("Invalid buffer size"),
            _ => Ok(()),
        };
        error.map_err(|e| $crate::Error::CryptoError(e.into()))?;
    }};
}

#[macro_export]
macro_rules! verify_auth {
    ($key:expr => [$key_size:expr], => [$buf:expr, $tag_size:expr]) => {{
        #[allow(unused_imports)]
        use $crate::verify::{SliceExt, USizeExt};

        let error = match true {
            _ if $key.constrain_value() != $key_size => Err("Invalid key length"),
            _ if $buf.constrain_value() < $tag_size => Err("Buffer is too small"),
            _ => Ok(()),
        };
        error.map_err(|e| $crate::Error::CryptoError(e.into()))?;
    }};
}

#[macro_export]
macro_rules! verify_encrypt {
    ($key:expr => [$key_size:expr], $nonce:expr => [$nonce_size:expr],
		$plaintext:expr => [$buf:expr, $plaintext_limit:expr]) => {{
        #[allow(unused_imports)]
        use $crate::verify::{SliceExt, USizeExt};

        let error = match true {
            _ if $key.constrain_value() != $key_size => Err("Invalid key length"),
            _ if $nonce.constrain_value() != $nonce_size => Err("Invalid nonce length"),
            _ if $plaintext.constrain_value() > $plaintext_limit => Err("Too much data"),
            _ if $plaintext.constrain_value() > $buf.constrain_value() => {
                Err("Buffer is too small")
            }
            _ => Ok(()),
        };
        error.map_err(|e| $crate::Error::CryptoError(e.into()))?;
    }};
}

#[macro_export]
macro_rules! verify_decrypt {
    ($key:expr => [$key_size:expr], $nonce:expr => [$nonce_size:expr],
		$ciphertext:expr => [$buf:expr, $ciphertext_limit:expr]) => {{
        #[allow(unused_imports)]
        use $crate::verify::{SliceExt, USizeExt};

        let error = match true {
            _ if $key.constrain_value() != $key_size => Err("Invalid key length"),
            _ if $nonce.constrain_value() != $nonce_size => Err("Invalid nonce length"),
            _ if $ciphertext.constrain_value() > $ciphertext_limit => Err("Too much data"),
            _ if $ciphertext.constrain_value() > $buf.constrain_value() => {
                Err("Buffer is too small")
            }
            _ => Ok(()),
        };
        error.map_err(|e| $crate::Error::CryptoError(e.into()))?;
    }};
}

#[macro_export]
macro_rules! verify_seal {
    ($key:expr => [$key_size:expr], $nonce:expr => [$nonce_const:expr],
		$plaintext:expr => [$buf:expr, $plaintext_limit:expr]) => {{
        #[allow(unused_imports)]
        use $crate::verify::{SliceExt, USizeExt};

        let error = match true {
            _ if $key.constrain_value() != $key_size => Err("Invalid key length"),
            _ if $nonce.constrain_value() != $nonce_const => Err("Invalid nonce length"),
            _ if $plaintext.constrain_value() > $plaintext_limit => Err("Too much data"),
            _ if $buf.constrain_value() < $plaintext.constrain_value() + CHACHAPOLY_TAG => {
                Err("Buffer is too small")
            }
            _ => Ok(()),
        };
        error.map_err(|e| $crate::Error::CryptoError(e.into()))?;
    }};
}

#[macro_export]
macro_rules! verify_open {
    ($key:expr => [$key_size:expr], $nonce:expr => [$nonce_size:expr],
		$ciphertext:expr => [$buf:expr, $tag_size:expr, $ciphertext_limit:expr]) => {{
        #[allow(unused_imports)]
        use $crate::verify::{SliceExt, USizeExt};

        let error = match true {
            _ if $key.constrain_value() != $key_size => Err("Invalid key length"),
            _ if $nonce.constrain_value() != $nonce_size => Err("Invalid nonce length"),
            _ if $ciphertext.constrain_value() > $ciphertext_limit => Err("Too much data"),
            _ if $ciphertext.constrain_value() < $tag_size => Err($crate::Error::InvalidData)?,
            _ if $buf.constrain_value() + $tag_size < $ciphertext.constrain_value() => {
                Err("Buffer is too small")
            }
            _ => Ok(()),
        };
        error.map_err(|e| $crate::Error::CryptoError(e.into()))?;
    }};
}
