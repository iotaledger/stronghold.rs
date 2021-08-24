// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use quote::{quote, ToTokens};
use syn::{
    AngleBracketedGenericArguments, Data, DataStruct, DeriveInput, Field, Fields, ImplGenerics, ItemImpl,
    PathArguments, PathSegment,
};

pub fn derive_source_target(derive_input: DeriveInput) -> proc_macro2::TokenStream {
    let proc_ident = derive_input.ident;
    let (impl_generics, ty_generics, where_clause) = derive_input.generics.split_for_impl();
    let mut impls = Vec::new();

    let for_self = quote! {#proc_ident #ty_generics #where_clause};

    let fields = match derive_input.data {
        Data::Struct(DataStruct {
            fields: Fields::Named(f),
            ..
        }) => Some(f.named),
        Data::Struct(DataStruct {
            fields: Fields::Unnamed(f),
            ..
        }) => Some(f.unnamed),
        _ => None,
    };

    if let Some(fields) = fields.as_ref() {
        for field in fields {
            if let Some(impl_) = impl_by_field(field, &impl_generics, &for_self) {
                impls.push(impl_)
            }
        }
    }
    impls.into_iter().collect()
}

fn impl_by_field(
    field: &Field,
    impl_generics: &ImplGenerics,
    for_self: &proc_macro2::TokenStream,
) -> Option<proc_macro2::TokenStream> {
    // panic!("field: {:?}", field);
    let field_ident = field.ident.clone();
    if field
        .attrs
        .iter()
        .any(|attr| attr.path.segments.last().unwrap().ident == "source_location")
    {
        Some(quote! {
            impl #impl_generics GetSourceVault for #for_self {
                fn get_source(&self) -> (VaultId, RecordId) {
                    self.#field_ident
                }
            }
        })
    } else if field
        .attrs
        .iter()
        .any(|attr| attr.path.segments.last().unwrap().ident == "target_location")
    {
        Some(quote! {
            impl #impl_generics GetTargetVault for #for_self {
                fn get_target(&self) -> (VaultId, RecordId, RecordHint) {
                    self.#field_ident
                }
            }
        })
    } else {
        None
    }
}

pub fn impl_exec_proc(item_impl: ItemImpl) -> proc_macro2::TokenStream {
    let panic_msg =
        "The proc_fn macro can only applied for implementation blocks of the traits `Generate`, `Process` or `Sink`";
    let self_type = item_impl.self_ty;
    let (impl_generics, _ty_generics, where_clause) = item_impl.generics.split_for_impl();

    let in_type: proc_macro2::TokenStream;
    let out_type: proc_macro2::TokenStream;

    let segment = item_impl
        .trait_
        .and_then(|t| t.1.segments.last().cloned())
        .expect(panic_msg);
    let generics = match segment.arguments {
        PathArguments::AngleBracketed(AngleBracketedGenericArguments { ref args, .. }) => args,
        _ => unreachable!(),
    };
    in_type = generics[0].to_token_stream();
    out_type = generics[1].to_token_stream();

    let gen_exec_fn = generate_fn_body(&segment, &in_type, &out_type);
    let impl_build;
    if format!("{}", in_type) == "()" {
        impl_build = quote! {
            impl #impl_generics #self_type #where_clause {
                pub fn build(self) -> BuildProcedure<Self> {
                    BuildProcedure {inner: self}
                }
            }
        }
    } else {
        impl_build = proc_macro2::TokenStream::new();
    }
    quote! {
        impl #impl_generics ExecProc for #self_type #where_clause {
            type InData = #in_type;
            type OutData = #out_type;

            fn exec<PExe: ProcExecutor>(self, executor: &mut PExe, input: Self::InData) -> Result<Self::OutData, anyhow::Error> {
                #gen_exec_fn
            }
        }
        #impl_build
    }
}

fn generate_fn_body(
    segment: &PathSegment,
    in_type: &proc_macro2::TokenStream,
    out_type: &proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    match format!("{}", segment.ident).as_str() {
        "Parser" => {
            quote! {
                <Self as Parser<#in_type, #out_type>>::parse(self, input).map_err(|e| anyhow::anyhow!(e))
            }
        }
        "Generate" => {
            quote! {
                let (vault_id_1, record_id_1, hint) = self.get_target();
                let ProcOutput {
                    write_vault,
                    return_value,
                } = <Self as Generate<#in_type, #out_type>>::generate(self, input)?;

                executor.write_to_vault(vault_id_1, record_id_1, hint, write_vault)?;
                Ok(return_value)
            }
        }
        "Process" => {
            quote! {
                let (vault_id_0, record_id_0) = self.get_source();
                let (vault_id_1, record_id_1, hint) = self.get_target();
                let f = move |input, guard| <Self as Process<#in_type, #out_type>>::process(self, input, guard);
                executor.exec_proc(
                    vault_id_0,
                    record_id_0,
                    vault_id_1,
                    record_id_1,
                    hint,
                    f,
                    input
                )
            }
        }
        "Sink" => {
            quote! {
                let (vault_id_0, record_id_0) = self.get_source();
                let f = move |input, guard| <Self as Sink<#in_type, #out_type>>::sink(self, input, guard);
                executor.get_guard(vault_id_0, record_id_0, f, input)
            }
        }
        _ => panic!(),
    }
}
