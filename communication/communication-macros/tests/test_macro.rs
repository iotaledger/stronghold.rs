// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use communication_macros::RequestPermissions;
use stronghold_communication::actor::firewall::{
    PermissionSum, PermissionValue, ToPermissionVariants, VariantPermission,
};

#[derive(RequestPermissions)]
enum TestEnum {
    Empty,
    Tuple(String),
    Struct { _inner: u32 },
}

#[test]
fn check_permissions() {
    let test_enum = TestEnum::Empty;
    assert_eq!(test_enum.to_permissioned().permission(), 1);
    for i in 0..10u32 {
        let should_permit = i % 2 == 1;
        assert_eq!(
            should_permit,
            PermissionSum::from(i).permits(&test_enum.to_permissioned().permission())
        );
    }

    let test_enum = TestEnum::Tuple(String::new());
    assert_eq!(test_enum.to_permissioned().permission(), 2);
    for i in 0..10u32 {
        let should_permit = i == 2 || i == 3 || i == 6 || i == 7;
        assert_eq!(
            should_permit,
            PermissionSum::from(i).permits(&test_enum.to_permissioned().permission())
        );
    }

    let test_enum = TestEnum::Struct { _inner: 42 };
    assert_eq!(test_enum.to_permissioned().permission(), 4);
    for i in 0..10u32 {
        let should_permit = i == 4 || i == 5 || i == 6 || i == 7;
        assert_eq!(
            should_permit,
            PermissionSum::from(i).permits(&test_enum.to_permissioned().permission())
        );
    }
}
