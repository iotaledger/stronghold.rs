// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use new_runtime::{memories::buffer::Buffer, DEBUG_MSG};

#[test]
fn buffer() {
    let data = &[1, 2, 3];
    let mut buf = Buffer::<u8>::alloc(data, 3);

    // Test debug
    assert_eq!(format!("{:?}", buf), DEBUG_MSG);
    assert_eq!(format!("{:?}", buf.borrow()), DEBUG_MSG);
    assert_eq!(format!("{:?}", buf.borrow_mut()), DEBUG_MSG);

    // Test functionality
    assert_eq!(&*buf.borrow(), data);
    buf.borrow_mut()[0] = 0;
    assert_eq!(&*buf.borrow(), &[0, 2, 3]);
}
