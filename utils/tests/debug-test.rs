// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use stronghold_utils::GuardDebug;

#[derive(GuardDebug)]
struct TestDebug {
    _field: String,
}

#[test]
fn test_guard_debug() {
    let test = TestDebug {
        _field: String::from("Some secret data"),
    };

    let str = format!("{:?}", test);

    assert_eq!(str, "TestDebug(guarded)");
}
