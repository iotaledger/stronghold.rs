// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use communication_macros::RequestPermissions;
use stronghold_communication::actor::firewall::{PermissionSum, ToPermissionVariants, VariantPermission};

#[derive(RequestPermissions)]
enum TestEnum {
    Empty,
    Tuple(String),
    Struct { _inner: u32 },
}

#[test]
fn check_permissions() {
    let test_enum = TestEnum::Empty;
    assert_eq!(test_enum.variant_permission_value(), 0);
    for i in 0..10 {
        let should_permit = i % 2 == 1;
        assert_eq!(should_permit, test_enum.is_permitted(i));
    }
    assert!(test_enum.is_permitted(1));
    assert!(!test_enum.is_permitted(2));

    let test_enum = TestEnum::Tuple(String::new());
    assert_eq!(test_enum.variant_permission_value(), 1);
    for i in 0..10 {
        let should_permit = i == 2 || i == 3 || i == 6 || i == 7;
        assert_eq!(should_permit, test_enum.is_permitted(i));
    }

    let test_enum = TestEnum::Struct { _inner: 42 };
    assert_eq!(test_enum.variant_permission_value(), 2);
    for i in 0..10 {
        let should_permit = i == 4 || i == 5 || i == 6 || i == 7;
        assert_eq!(should_permit, test_enum.is_permitted(i));
    }
}
