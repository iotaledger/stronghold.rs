// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// links the macos security framework to the lib
#[cfg(any(target_os = "macos", target_os = "ios"))]
#[allow(unnecessary_wraps)]
fn macos_secrandom() -> Option<&'static str> {
    println!("cargo:rustc-link-lib=framework=Security");
    Some("USE_SECRANDOM")
}

// checks if the current version of glibc supports the getrandom function
#[cfg(target_os = "linux")]
#[allow(unnecessary_wraps)]
fn linux_check_getrandom() -> Option<&'static str> {
    use std::{ffi::CStr, os::raw::c_char, str::FromStr};
    extern "C" {
        fn gnu_get_libc_version() -> *const c_char;
    }

    let v: Vec<u8> = unsafe { CStr::from_ptr(gnu_get_libc_version()) }
        .to_str()
        .unwrap()
        .split('.')
        .map(|s| u8::from_str(s).unwrap())
        .collect();

    match (v[0], v[1]) {
        (2..=255, 25..=255) => Some("USE_GETRANDOM"),
        _ => Some("USE_DEV_RANDOM"),
    }
}

fn main() {
    // determine which secure random number generator should be used.
    #[allow(unused_assignments)]
    let mut secure_random = None;

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        secure_random = macos_secrandom()
    }
    #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
    {
        secure_random = Some("USE_ARC4RANDOM")
    }
    #[cfg(target_os = "windows")]
    {
        println!("cargo:rustc-link-lib=bcrypt");
        secure_random = Some("USE_CRYPTGENRANDOM")
    }
    #[cfg(target_os = "android")]
    {
        secure_random = Some("USE_DEV_RANDOM")
    }
    #[cfg(target_os = "linux")]
    {
        // somehow when compiling to `i686-linux-android` the target_os is still pointing to `linux`
        let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
        secure_random = match target_os.as_str() {
            "linux" => linux_check_getrandom(),
            "android" => Some("USE_DEV_RANDOM"),
            _ => None,
        }
    }

    // check to see if there is a specified RNG
    let secure_random = secure_random.expect("No secure random number generator known for the target platform");

    // build and compile the library.
    cc::Build::new()
        .file("c_src/rng.c")
        .define(secure_random, None)
        .warnings_into_errors(true)
        .compile("rng");
    println!("cargo:rustc-link-lib=static=rng");
}
