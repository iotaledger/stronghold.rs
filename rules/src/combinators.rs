// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[allow(unused_imports)]
use core::iter::Iterator;

pub struct Rule(usize);

impl Rule {
    fn get(&self) -> usize {
        self.0
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn build_rule() {
        let rule = Rule(0);
        let r = rule.0;
    }
}
