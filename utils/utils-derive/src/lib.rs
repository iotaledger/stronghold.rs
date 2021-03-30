// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Proc macros for Stronghold.

#![warn(missing_docs)]
#![no_std]

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

/// A version of the Debug macro that blocks parsing the data inside of a struct or enum.
#[proc_macro_derive(GuardDebug)]
pub fn derive_guard_debug(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let ident = input.ident;

    let (generics, types, _) = input.generics.split_for_impl();

    let generated = quote! {
        impl #generics core::fmt::Debug for #ident #types {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                f.debug_struct(concat!(stringify!(#ident), "(guarded)")).finish()
            }
        }
    };

    generated.into()
}
