// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

extern crate proc_macro;

use proc_macro2::{Ident, TokenStream};
use quote::{quote, ToTokens};
use syn::{punctuated::Punctuated, token::Comma, Data, DataEnum, DeriveInput, Fields};

/// Implements the [`VariantPermission`] for struct/ unions with PermissionValue(1).
/// For enums, it implements [`ToPermissionVariants`], which creates an according new enum <Ident>Permission with Unit
/// variants, and implements [`VariantPermission`] by assigning a permission value for each variant.
/// The permission value is the "index" in the enum as exponent for the power of 2, thus from top to bottom 1, 2, 4,
/// 8... This enables using it within the [`CommunicationActor`] and allows the [`CommunicationFirewall`] to handle it.
#[proc_macro_derive(RequestPermissions)]
pub fn permissions(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let derive_input = syn::parse_macro_input!(input as DeriveInput);
    let name = format!("{}Permission", derive_input.ident);
    let name = syn::Ident::new(&name, derive_input.ident.span());
    let gen = match derive_input.data {
        Data::Enum(data_enum) => {
            let unit_enum = build_plain(&name, &data_enum);
            let impl_permission = impl_permission(&name, &data_enum);
            let to_permissioned = impl_to_permissioned(&derive_input.ident, &name, &data_enum);

            quote! {
                #unit_enum
                #impl_permission
                #to_permissioned
            }
        }
        Data::Struct(_) | Data::Union(_) => {
            let ident = derive_input.ident.clone();
            quote! {
                impl VariantPermission for #ident {
                    fn permission(&self) -> PermissionValue {
                        1
                    }
                    fn is_permitted(&self, permission: PermissionValue) -> bool {
                        permission % 2 != 0
                    }
                }

            }
        }
    };
    gen.into()
}

fn build_plain(name: &Ident, data_enum: &DataEnum) -> TokenStream {
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

fn match_fields(fields: &Fields) -> TokenStream {
    match fields {
        Fields::Unit => TokenStream::new(),
        Fields::Unnamed(fields_unnamed) => {
            let blanked = fields_unnamed
                .unnamed
                .iter()
                .map(|_| quote! {_})
                .collect::<Punctuated<TokenStream, Comma>>()
                .to_token_stream();
            quote! { (#blanked) }
        }
        Fields::Named(fields_named) => {
            let blanked = fields_named
                .named
                .iter()
                .filter_map(|field| {
                    if let Some(ident) = field.ident.as_ref() {
                        Some(quote! {#ident: _})
                    } else {
                        None
                    }
                })
                .collect::<Punctuated<TokenStream, Comma>>()
                .to_token_stream();
            quote! { { #blanked } }
        }
    }
}

fn impl_to_permissioned(input: &Ident, name: &Ident, data_enum: &DataEnum) -> TokenStream {
    let match_variants = data_enum
        .variants
        .iter()
        .map(|variant| {
            let ident = variant.ident.clone();
            let fields = match_fields(&variant.fields);
            quote! {
                #input::#ident#fields => #name::#ident,
            }
        })
        .collect::<TokenStream>();
    quote! {
        impl ToPermissionVariants<#name> for #input {
            fn to_permissioned(&self) -> #name {
                match self {
                    #match_variants
                }
            }
        }
    }
}

fn impl_permission(name: &Ident, data_enum: &DataEnum) -> TokenStream {
    if data_enum.variants.len() > 32 {
        panic!("More then 32 variants on enums are not allowed.");
    }
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
                PermissionValue::new(n)
            }
        }
    }
}
