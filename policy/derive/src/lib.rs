// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! derive macro crate for policy engine

use proc_macro::*;
use quote::quote;

/// Derives [`Cardinality`] for enum types
#[proc_macro_derive(Cardinality)]
pub fn derive_enum_cardinality(input: TokenStream) -> TokenStream {
    let item: syn::DeriveInput = syn::parse(input).unwrap();

    let name = item.clone().ident;
    let generics = item.clone().generics;
    let (impl_generics, type_generics, where_clause) = generics.split_for_impl();

    let size = match item.data {
        syn::Data::Enum(enum_item) => enum_item.variants.len(),
        _ => panic!("Deriving the `Cardinality` trait only works on enums so far"),
    };

    let expanded = quote! {
        impl #impl_generics Cardinality for #name #type_generics #where_clause {
            fn cardinality() -> usize {
                #size
            }
        }
    };
    expanded.into()
}
