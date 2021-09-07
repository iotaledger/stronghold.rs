// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Proc macros for Stronghold.
#![warn(missing_docs)]

mod comm;
mod procs;
use comm::{build_plain, impl_permission, impl_to_permissioned};

use proc_macro::TokenStream;

use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, ItemImpl};

use crate::procs::{impl_exec_proc, impl_proc_traits};

/// A version of the derive [`Debug`] trait that blocks parsing the data inside of a struct or enum.
/// Use [`GuardDebug`] to block reading and inspection of a data structure via the [`Debug`] trait.
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

/// Implements the `VariantPermission` for struct/ unions with PermissionValue(1).
/// For enums, it creates an analogous new enum <Ident>Permission with Unit variants, and implements `VariantPermission`
/// by assigning different `PermissionValue` for each variant. The permission value is the "index" in the enum as
/// exponent for the power of 2, thus from top to bottom 1, 2, 4, 8...
/// Additionally, it implements `Borrow` from the new original enum to the new enum, to satisfy the trait bounds of
/// `StrongholdP2p`.
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
                        // Only panics for values > 31.
                        PermissionValue::new(0).unwrap()
                    }
                }

            }
        }
    };
    gen.into()
}

///
#[proc_macro_derive(Procedure, attributes(source, target, input_data, output_key))]
pub fn derive_exec_proc(input: TokenStream) -> proc_macro::TokenStream {
    let derive_input = syn::parse_macro_input!(input as DeriveInput);
    let tokens = impl_proc_traits(derive_input);
    tokens.into()
}

///
#[proc_macro_attribute]
pub fn execute_procedure(_attr: proc_macro::TokenStream, mut item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let item_clone = item.clone();
    let item_impl = syn::parse_macro_input!(item_clone as ItemImpl);
    let gen: proc_macro::TokenStream = impl_exec_proc(item_impl).into();
    item.extend(gen);
    item
}
