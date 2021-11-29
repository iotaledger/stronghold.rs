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

use crate::procs::{impl_proc_traits, impl_procedure_step};

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

/// _Internal macro to help implementation of primitive procedures in `iota-stronghold`_.
///
/// Auto-implement the traits `SourceInfo`, `TargetInfo`, `InputInfo` and `OutputInfo` that are required to
/// derive the `ProcedureStep` trait with the [`execute_procedure`] attribute macro.
/// To derive a traits, annotate the structure's field that contains the information.
/// It is required that the annotated type itself implements the trait.
/// E.g. in case of
/// ```compile_fail
/// #[derive(Procedure)]
/// struct PublicKey {
///     #[source]
///     source: Location,
///
///     #[output_key]
///     output_key: TempOutput,
/// }
/// ```
/// the macro generates
/// ```compile_fail
/// impl SourceInfo for PublicKey {
///     fn source_location(&self) -> &Location {
///         self.source.source_location()
///     }
///
///     fn source_location_mut(&mut self) -> &mut Location {
///         self.source.source_location_mut()
///     }
/// }
///
/// impl OutputInfo for PublicKey {
///     fn output_info(&self) -> &TempOutput {
///         self.output_key.output_info()
///     }
///     fn output_info_mut(&mut self) -> &mut TempOutput {
///         self.output_key.output_info_mut()
///     }
/// }
/// ```
#[proc_macro_derive(Procedure, attributes(source, target, input_data, output_key))]
pub fn derive_procedure(input: TokenStream) -> proc_macro::TokenStream {
    let derive_input = syn::parse_macro_input!(input as DeriveInput);
    let tokens = impl_proc_traits(derive_input);
    tokens.into()
}

/// _Internal macro to help implementation of primitive procedures in `iota-stronghold`_.
///
/// Implements the `ProcedureStep` trait.
///
/// To be placed at the impl block of one of the following traits:
/// `ProcessData`, `GenerateSecret`, `DeriveSecret`, `UseSecret`.
/// The macro implements the logic for fetching the source secret and input type, and writing the output into the
/// `CollectedOutput` and new secrets into the vault.
///
/// For `GenerateSecret` & `DeriveSecret` it is expected that the `TargetInfo` trait is implemented to describe
/// where the new secret should be written, and for `DeriveSecret` & `UseSecret` the `SourceInfo` trait is required to
/// specify the location of the existing secret that should be used.
/// Each of the 4 traits defines associated types to set the type of non-secret Input and Output.
/// If the `Input` type is **not** (), is is expected that the `InputInfo` trait is implemented to set where the input
/// data should be gathered from, analogous for `Output` that is **not** (), `OutputInfo` has to be implemented.
///
/// `TargetInfo`, `SourceInfo`, `InputInfo` and `OutputInfo` can be derived with the [`Procedure`] proc macro.
///
/// ## Example
/// ```compile_fail
/// #[derive(Procedure)]
/// pub struct PublicKey {
///     #[source]
///     private_key: Location,
///
///     #[output_key]
///     write_output: TempOutput,
/// }
///
/// #[execute_procedure]
/// impl UseSecret for PublicKey {
///     type Input = ();
///     type Output = Vec<u8>;
///
///     fn use_secret(self, _: Self::Input, guard: GuardedVec<u8>) -> Result<Self::Output, FatalProcedureError> {
///         todo!("Implement the procedure's actual logic.")
///     }
/// }
/// ```
#[proc_macro_attribute]
pub fn execute_procedure(_attr: proc_macro::TokenStream, mut item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let item_clone = item.clone();
    let item_impl = syn::parse_macro_input!(item_clone as ItemImpl);
    let gen: proc_macro::TokenStream = impl_procedure_step(item_impl).into();
    item.extend(gen);
    item
}
