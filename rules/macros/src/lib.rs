// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! macro crate for rules engine

use proc_macro::*;
use quote::quote;
use std::str::FromStr;

#[proc_macro]
/// Interceptor macro
///
/// This structural macro will take an empty struct being used
/// as the interceptor object: an object, that will intercept all calls
/// from given generic trait bound on the empty struct.
pub fn intercept(_input: proc_macro::TokenStream) -> TokenStream {
    todo!()
}

#[proc_macro]
/// Creates a rule to be used for the rules engine.
/// a rules basically consists of two parts
/// - a condition that matches on some input
/// - an action, that will be executed if the condition has been triggered.
///
/// Creating a rule is straightforward:
/// ```no_run
/// use stronghold_rules as rules;
///
/// let mut engine = rules::engine::RulesEngine::default();
/// engine.insert(rule!("allow incoming requests",));
/// ```
pub fn rule(_input: proc_macro::TokenStream) -> TokenStream {
    todo!()
}

#[proc_macro]
pub fn impl_count_tuples(input: proc_macro::TokenStream) -> TokenStream {
    let count = input.to_string().parse().unwrap();

    (1..count)
        .into_iter()
        .map(|n| {
            let mut generics = alphabetical(n).collect::<Vec<String>>().join(",");
            if n == 1 {
                generics.push(',')
            };
            let generics_tokens = proc_macro2::TokenStream::from_str(&generics).unwrap();

            quote! {
                impl<#generics_tokens> Count for (#generics_tokens) {
                    fn count(&self) -> usize {
                        #n
                    }
                }
            }
        })
        .collect::<proc_macro2::TokenStream>()
        .into()
}

/// Returns an iterator of [`String`]s of the alphabet (A-Z). If the last character
/// is 'Z', the next string returned will be 'AA'.
fn alphabetical(count: usize) -> impl Iterator<Item = String> {
    let radix = 26;
    let end = ('A' as usize + radix) as u8 as char;
    let digits = (count as f64).log(radix as f64) as usize;
    let alpha = ('A'..end).collect::<Vec<char>>();

    (0..count).map(move |i| {
        let mut div = i;
        let mut index = 0;

        let mut result = vec!['A'; digits + 1];

        while div != 0 {
            if index > 0 {
                div -= 1;
            }
            let a_index = div % radix;
            result[digits - index] = alpha[a_index];
            index += 1;
            div /= radix;
        }

        result.iter().collect::<String>()
    })
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_alphabet_iterator() {
        let mut iter = alphabetical(32).skip(28);

        assert_eq!(iter.next(), Some("AC".to_string()));
        assert_eq!(iter.next(), Some("AD".to_string()));
        assert_eq!(iter.next(), Some("AE".to_string()));
        assert_eq!(iter.next(), Some("AF".to_string()));
        assert_eq!(iter.next(), None);
    }
}
