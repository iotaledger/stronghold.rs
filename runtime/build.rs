// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

extern crate bindgen;

#[cfg(target_os = "linux")]
fn main() {
    use std::{env, path::PathBuf};
    println!("cargo:rerun-if-changed=src/seccomp.h");

    bindgen::Builder::default()
        .header("src/seccomp.h")
        .ctypes_prefix("libc")
        .use_core()
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(PathBuf::from(env::var("OUT_DIR").unwrap()).join("seccomp_bindings.rs"))
        .expect("Couldn't write bindings!");
}

#[cfg(not(target_os = "linux"))]
fn main() {}
