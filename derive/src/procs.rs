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

    impls.into_iter().collect()
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
        .any(|attr| attr.path.segments.last().unwrap().ident == "source")
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
        .any(|attr| attr.path.segments.last().unwrap().ident == "target")
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
            quote! {SourceInfo},
            None,
            quote! {source_location},
            quote! {source_location_mut},
            quote! {Location},
        ),
        IOTrait::TargetVault => (
            quote! {TargetInfo},
            None,
            quote! {target_info},
            quote! {target_info_mut},
            quote! {TempTarget},
        ),
        IOTrait::InputData(ty) => (
            quote! {InputInfo},
            Some(quote! {type Input = <#ty as InputInfo>::Input; }),
            quote! {input_info},
            quote! {input_info_mut},
            quote! {InputData<Self::Input>},
        ),
        IOTrait::OutputKey => (
            quote! {OutputInfo},
            None,
            quote! {output_info},
            quote! {output_info_mut},
            quote! {TempOutput},
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

// `execute_procedure` macro logic

pub fn impl_procedure_step(item_impl: ItemImpl) -> proc_macro2::TokenStream {
    let panic_msg =
        "The execute_procedure macro can only applied for implementation blocks of the traits `GenerateSecret`, `ProcessData` or `UseSecret`.";

    let segment = item_impl
        .trait_
        .and_then(|t| t.1.segments.last().cloned())
        .expect(panic_msg);

    let mut has_input = false;
    let mut returns_data = false;
    for item in item_impl.items {
        if let ImplItem::Type(ImplItemType { ident, ty, .. }) = item {
            let is_empty_tuple = matches!(ty, Type::Tuple(TypeTuple{elems, ..}) if elems.is_empty());
            if ident == "Input" && !is_empty_tuple {
                has_input = true;
            } else if ident == "Output" && !is_empty_tuple {
                returns_data = true;
            }
        }
    }
    let gen_exec_fn = generate_fn_body(&segment, has_input, returns_data);
    let self_type = item_impl.self_ty;
    let (impl_generics, _, where_clause) = item_impl.generics.split_for_impl();

    quote! {
        impl #impl_generics ProcedureStep for #self_type #where_clause {
            fn execute<X: Runner>(self, runner: &mut X, state: &mut State) -> Result<(), ProcedureError> {
                #gen_exec_fn
            }
        }
    }
}

fn generate_fn_body(segment: &PathSegment, has_input: bool, returns_data: bool) -> proc_macro2::TokenStream {
    let gen_input = if has_input {
        quote! {
            let input_data = <Self as InputInfo>::input_info(&self);
            let input = match input_data {
                InputData::Value(v) => v.clone(),
                InputData::Key(key) => {
                    let data = state.get_output(&key).ok_or(ProcedureError::MissingInput)?.clone();
                    <Self as InputInfo>::Input::try_from_procedure_io(data).map_err(|_| ProcedureError::InvalidInput)?
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
            let TempOutput {
                write_to: key,
                is_temp: is_out_data_temp
            } = <Self as OutputInfo>::output_info(&self).clone();
        };
        gen_insert_data = quote! {
           state.insert_output(key, output.into_procedure_io(), is_out_data_temp);
        }
    } else {
        gen_output_key = quote! {};
        gen_insert_data = quote! {};
    };
    match segment.ident.to_string().as_str() {
        "ProcessData" => quote! {
                #gen_input
                #gen_output_key
                let output = <Self as ProcessData>::process(self, input)?;
                #gen_insert_data
                Ok(())
        },
        "GenerateSecret" => quote! {
                let TempTarget  {
                    write_to: Target { location: location_1, hint },
                    is_temp: is_secret_temp
                } = <Self as TargetInfo>::target_info(&self).clone();
                #gen_input
                #gen_output_key
                let Products {
                    secret,
                    output,
                } = <Self as GenerateSecret>::generate(self, input)?;
                runner.write_to_vault(&location_1, hint, secret)?;
                state.add_log(location_1, is_secret_temp);
                #gen_insert_data
                Ok(())
        },
        "DeriveSecret" => quote! {
                let location_0 = <Self as SourceInfo>::source_location(&self).clone();
                let TempTarget  {
                    write_to: Target { location: location_1, hint },
                    is_temp: is_secret_temp
                } = <Self as TargetInfo>::target_info(&self).clone();
                #gen_input
                #gen_output_key
                let f = move |guard| <Self as DeriveSecret>::derive(self, input, guard);
                let output = runner.exec_proc(
                    &location_0,
                    &location_1,
                    hint,
                    f,
                )?;
                state.add_log(location_1, is_secret_temp);
                #gen_insert_data
                Ok(())
        },
        "UseSecret" => quote! {
            let location_0 = <Self as SourceInfo>::source_location(&self).clone();
            #gen_output_key
            #gen_input
            let f = move |guard| <Self as UseSecret>::use_secret(self, input, guard);
            let output = runner.get_guard(&location_0, f)?;
            #gen_insert_data
            Ok(())
        },
        _ => panic!(),
    }
}
