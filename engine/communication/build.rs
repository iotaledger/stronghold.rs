// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

fn main() {
    prost_build::Config::new()
        .btree_map(&["."])
        .compile_protos(&["src/behaviour/structs.proto"], &["src"])
        .unwrap();
}
