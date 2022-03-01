// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use proc_macro2::{Ident, TokenStream};
use quote::quote;
use syn::{DataEnum, Fields};

pub fn build_plain(name: &Ident, data_enum: &DataEnum) -> TokenStream {
    let plain_variants = data_enum
        .variants
        .iter()
        .map(|variant| {
            let ident = variant.ident.clone();
            quote! {
                    #ident,
            }
        })
        .collect::<TokenStream>();
    quote! {
            #[derive(Clone, Debug)]
            pub enum #name {
                #plain_variants
            }
    }
}

pub fn match_fields(fields: &Fields) -> TokenStream {
    match fields {
        Fields::Unit => TokenStream::new(),
        Fields::Unnamed(..) => quote! { (..) },
        Fields::Named(..) => quote! { { .. } },
    }
}

pub fn impl_to_permissioned(input: &Ident, name: &Ident, data_enum: &DataEnum) -> TokenStream {
    let match_variants = data_enum
        .variants
        .iter()
        .map(|variant| {
            let ident = variant.ident.clone();
            let fields = match_fields(&variant.fields);
            quote! {
                #input::#ident #fields => #name::#ident,
            }
        })
        .collect::<TokenStream>();
    quote! {
        impl FwRequest<#input> for #name {
            fn from_request(request: &#input) -> Self {
                match request {
                    #match_variants
                }
            }
        }
    }
}

pub fn impl_permission(name: &Ident, data_enum: &DataEnum) -> TokenStream {
    assert!(
        data_enum.variants.len() <= 32,
        "More then 32 variants on enums are not supported."
    );

    let mut i = 0u8;
    let permissions = data_enum
        .variants
        .iter()
        .map(|variant| {
            let ident = variant.ident.clone();
            let p = quote! {
                #name::#ident => #i,
            };
            i += 1;
            p
        })
        .collect::<TokenStream>();
    quote! {
        impl VariantPermission for #name {
            fn permission(&self) -> PermissionValue {
                let n = match self {
                    #permissions
                };
                // Only panics if the enum has more than 32 variants, which has already been checked.
                PermissionValue::new(n).unwrap()
            }
        }
    }
}
