// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use communication::actor::{
    FirewallPermission, PermissionValue, RequestPermissions, ToPermissionVariants, VariantPermission,
};

#[derive(RequestPermissions)]
enum TestEnum {
    Empty,
    Tuple(String),
    Struct { _inner: u32 },
}

#[test]
fn enum_permissions() {
    let test_enum = TestEnum::Empty.to_permissioned();
    assert_eq!(test_enum.permission(), 1);
    for i in 0..10u32 {
        let should_permit = i % 2 == 1;
        assert_eq!(
            should_permit,
            FirewallPermission::from(i).permits(&test_enum.permission())
        );
    }

    let test_enum = TestEnum::Tuple(String::new()).to_permissioned();
    assert_eq!(test_enum.permission(), 2);
    for i in 0..10u32 {
        let should_permit = i == 2 || i == 3 || i == 6 || i == 7;
        assert_eq!(
            should_permit,
            FirewallPermission::from(i).permits(&test_enum.permission())
        );
    }

    let test_enum = TestEnum::Struct { _inner: 42 }.to_permissioned();
    assert_eq!(test_enum.permission(), 4);
    for i in 0..10u32 {
        let should_permit = i == 4 || i == 5 || i == 6 || i == 7;
        assert_eq!(
            should_permit,
            FirewallPermission::from(i).permits(&test_enum.permission())
        );
    }
}

#[derive(RequestPermissions, Clone)]
struct TestStruct;

#[test]
fn struct_permission() {
    let test_struct = TestStruct;
    assert_eq!(test_struct.permission(), 1);
    for i in 0..10u32 {
        let should_permit = i % 2 == 1;
        assert_eq!(
            should_permit,
            FirewallPermission::from(i).permits(&test_struct.permission())
        );
    }
    // test blanked implementation of `ToPermissionVariants`
    assert_eq!(test_struct.to_permissioned().permission(), 1);
}

#[derive(RequestPermissions, Clone, Copy)]
union TestUnion {
    _inner: i16,
}

#[test]
fn union_permission() {
    let test_union = TestUnion { _inner: 0 };
    assert_eq!(test_union.permission(), 1);
    for i in 0..10u32 {
        let should_permit = i % 2 == 1;
        assert_eq!(
            should_permit,
            FirewallPermission::from(i).permits(&test_union.permission())
        );
    }
    // test blanked implementation of `ToPermissionVariants`
    assert_eq!(test_union.to_permissioned().permission(), 1);
}
