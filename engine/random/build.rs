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

// links the macos security framework to the lib
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn macos_secrandom() -> Option<&'static str> {
    println!("cargo:rustc-link-lib=framework=Security");
    Some("USE_SECRANDOM")
}

// checks if the current version of glibc supports the getrandom function
#[cfg(target_os = "linux")]
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
    #[cfg(target_os = "linux")]
    {
        secure_random = linux_check_getrandom()
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
