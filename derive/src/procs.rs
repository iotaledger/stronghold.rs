// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use proc_macro2::Ident;
use quote::quote;
use syn::{
    Data, DataStruct, DeriveInput, Field, Fields, GenericParam, Generics, ImplItem, ImplItemType, ItemImpl, Path,
    PathSegment, Type, TypePath, TypeTuple,
};

pub fn impl_proc_traits(derive_input: DeriveInput) -> proc_macro2::TokenStream {
    let fields = match derive_input.data.clone() {
        Data::Struct(DataStruct {
            fields: Fields::Named(f),
            ..
        }) => f.named,
        _ => return proc_macro2::TokenStream::new(),
    };

    let proc_ident = derive_input.ident.clone();
    let mut impls = Vec::new();

    for field in fields {
        impl_source_target(&mut impls, &field, &derive_input.generics, &proc_ident)
    }

    // implement BuildProc trait
    impl_build_proc(&mut impls, &proc_ident, derive_input.generics);

    impls.into_iter().collect()
}

fn impl_build_proc(impls: &mut Vec<proc_macro2::TokenStream>, ident: &Ident, generics: Generics) {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    impls.push(
        quote! {impl #impl_generics BuildProc<Self> for #ident #ty_generics #where_clause {
            fn build(self) -> ComplexProc<Self> {
                ComplexProc {inner: self}
            }
        }},
    )
}

fn impl_source_target(
    impls: &mut Vec<proc_macro2::TokenStream>,
    field: &Field,
    generics: &Generics,
    proc_ident: &Ident,
) {
    let field_ident = match field.ident {
        Some(ref i) => i,
        None => return,
    };
    let field_type = &field.ty;
    if field
        .attrs
        .iter()
        .any(|attr| attr.path.segments.last().unwrap().ident == "source_location")
    {
        impl_get_location(
            impls,
            IOTrait::SourceVault,
            proc_ident,
            field_ident,
            field_type,
            generics.clone(),
        );
    }
    if field
        .attrs
        .iter()
        .any(|attr| attr.path.segments.last().unwrap().ident == "target_location")
    {
        impl_get_location(
            impls,
            IOTrait::TargetVault,
            proc_ident,
            field_ident,
            field_type,
            generics.clone(),
        );
    }
    if field
        .attrs
        .iter()
        .any(|attr| attr.path.segments.last().unwrap().ident == "input_data")
    {
        impl_get_location(
            impls,
            IOTrait::InputData(&field.ty),
            proc_ident,
            field_ident,
            field_type,
            generics.clone(),
        );
    }
    if field
        .attrs
        .iter()
        .any(|attr| attr.path.segments.last().unwrap().ident == "output_key")
    {
        impl_get_location(
            impls,
            IOTrait::OutputKey,
            proc_ident,
            field_ident,
            field_type,
            generics.clone(),
        );
    }
}

enum IOTrait<'a> {
    SourceVault,
    TargetVault,
    InputData(&'a Type),
    OutputKey,
}

fn impl_get_location(
    impls: &mut Vec<proc_macro2::TokenStream>,
    io_trait: IOTrait,
    proc_ident: &Ident,
    field_ident: &Ident,
    field_type: &Type,
    generics: Generics,
) {
    let (trait_name, at, fn_name, fn_name_mut, return_type) = match io_trait {
        IOTrait::SourceVault => (
            quote! {SourceVaultInfo},
            None,
            quote! {source_location},
            quote! {source_location_mut},
            quote! {Location},
        ),
        IOTrait::TargetVault => (
            quote! {TargetVaultInfo},
            None,
            quote! {target_info},
            quote! {target_info_mut},
            quote! {(Location, RecordHint, bool)},
        ),
        IOTrait::InputData(ty) => (
            quote! {InputDataInfo},
            Some(quote! {type InData = <#ty as InputDataInfo>::InData; }),
            quote! {input_info},
            quote! {input_info_mut},
            quote! {InputData<Self::InData>},
        ),
        IOTrait::OutputKey => (
            quote! {OutputDataInfo},
            None,
            quote! {output_info},
            quote! {output_info_mut},
            quote! {(DataKey, bool)},
        ),
    };

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let mut gen_where_clause = quote! {#where_clause};

    // Add trait bound in case of a generic field type.
    if let Type::Path(TypePath {
        path: Path { segments, .. },
        ..
    }) = field_type
    {
        if let Some(type_ident) = segments.last().map(|s| &s.ident) {
            if generics
                .params
                .iter()
                .any(|p| matches!(p, GenericParam::Type(t) if &t.ident == type_ident))
            {
                gen_where_clause = where_clause
                    .map(|w| quote! {#w  #field_type: #trait_name})
                    .unwrap_or_else(|| quote! { where #field_type: #trait_name})
            }
        }
    }
    impls.push(quote! {
        impl #impl_generics #trait_name for #proc_ident #ty_generics #gen_where_clause {
            #at
            fn #fn_name(&self) -> &#return_type {
                self.#field_ident.#fn_name()
            }
            fn #fn_name_mut(&mut self) -> &mut #return_type {
                self.#field_ident.#fn_name_mut()
            }
        }
    })
}

// `proc_fn` macro logic

pub fn impl_exec_proc(item_impl: ItemImpl) -> proc_macro2::TokenStream {
    let panic_msg =
        "The proc_fn macro can only applied for implementation blocks of the traits `Generate`, `Process` or `Sink`.";

    let segment = item_impl
        .trait_
        .and_then(|t| t.1.segments.last().cloned())
        .expect(panic_msg);

    let mut has_input = false;
    let mut returns_data = false;
    for item in item_impl.items {
        if let ImplItem::Type(ImplItemType { ident, ty, .. }) = item {
            let is_empty_tuple = matches!(ty, Type::Tuple(TypeTuple{elems, ..}) if elems.is_empty());
            if ident == "InData" && !is_empty_tuple {
                has_input = true;
            } else if ident == "OutData" && !is_empty_tuple {
                returns_data = true;
            }
        }
    }
    let gen_exec_fn = generate_fn_body(&segment, has_input, returns_data);
    let self_type = item_impl.self_ty;
    let (impl_generics, ty_generics, where_clause) = item_impl.generics.split_for_impl();

    quote! {
        impl #impl_generics ExecProc for #self_type #ty_generics #where_clause {
            fn exec<X: ProcExecutor>(self, executor: &mut X, state: &mut ProcState) -> Result<(), anyhow::Error> {
                #gen_exec_fn
            }
        }
    }
}

fn generate_fn_body(segment: &PathSegment, has_input: bool, returns_data: bool) -> proc_macro2::TokenStream {
    let gen_input = if has_input {
        quote! {
            let input_data = self.input_info();
            let input = match input_data {
                InputData::Value(v) => v.clone(),
                InputData::Key {key, convert} => {
                    let data = state.get_data(&key)?;
                    convert(data)?
                }
            };
        }
    } else {
        quote! {let input = (); }
    };
    let gen_output_key;
    let gen_insert_data;
    if returns_data {
        gen_output_key = quote! {
            let (key, is_out_data_temp) = self.output_info().clone();
        };
        gen_insert_data = quote! {
           state.insert_data(key, return_value.into(), is_out_data_temp);
        }
    } else {
        gen_output_key = quote! {};
        gen_insert_data = quote! {};
    };
    match segment.ident.to_string().as_str() {
        "Parse" => quote! {
                #gen_input
                #gen_output_key
                let return_value = <Self as Parse>::parse(self, input)?;
                #gen_insert_data
                Ok(())
        },
        "Generate" => quote! {
                let (location_1, hint, is_secret_temp) = self.target_info().clone();
                #gen_input
                #gen_output_key
                let ProcOutput {
                    write_vault,
                    return_value,
                } = <Self as Generate>::generate(self, input)?;
                executor.write_to_vault(&location_1, hint, write_vault)?;
                state.add_log(location_1, is_secret_temp);
                #gen_insert_data
                Ok(())
        },
        "Process" => quote! {
                let location_0 = self.source_location().clone();
                let (location_1, hint, is_secret_temp) = self.target_info().clone();
                #gen_input
                #gen_output_key
                let f = move |input, guard| <Self as Process>::process(self, input, guard);
                let return_value = executor.exec_proc(
                    &location_0,
                    &location_1,
                    hint,
                    f,
                    input
                )?;
                state.add_log(location_1, is_secret_temp);
                #gen_insert_data
                Ok(())
        },
        "Sink" => quote! {
            let location_0 = self.source_location().clone();
            #gen_output_key
            #gen_input
            let f = move |input, guard| <Self as Sink>::sink(self, input, guard);
            let return_value = executor.get_guard(&location_0, f, input)?;
            #gen_insert_data
            Ok(())
        },
        _ => panic!(),
    }
}
