extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn seccomp_bindings() {
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

fn main() {
    seccomp_bindings();
}
