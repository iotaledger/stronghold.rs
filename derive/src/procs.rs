// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use proc_macro2::Ident;
use quote::quote;
use syn::{
    punctuated::Punctuated, token::Comma, Data, DataStruct, DeriveInput, Field, Fields, GenericParam, Generics,
    ImplItem, ImplItemType, ItemImpl, Path, PathSegment, Type, TypePath,
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

    let dyn_proc_ident = gen_dyn_input_proc(&mut impls, &derive_input, &fields);

    for field in fields {
        impl_source_target(&mut impls, &field, &derive_input.generics, &proc_ident, &dyn_proc_ident)
    }

    // implement BuildProc trait
    impl_build_proc(&mut impls, &proc_ident, derive_input.generics.clone());
    if let Some(dyn_proc_ident) = dyn_proc_ident {
        impl_build_proc(&mut impls, &dyn_proc_ident, derive_input.generics);
    }

    impls.into_iter().collect()
}

pub fn gen_dyn_input_proc(
    impls: &mut Vec<proc_macro2::TokenStream>,
    derive_input: &DeriveInput,
    fields: &Punctuated<Field, Comma>,
) -> Option<syn::Ident> {
    // Extract the "input"-field from the other fields
    let mut input_field = None;
    let other_fields: Punctuated<Field, Comma> = fields
        .into_iter()
        .filter_map(|f| {
            if f.attrs.iter().any(|a| a.path.segments.last().unwrap().ident == "input") {
                input_field = Some(f.clone());
                None
            } else {
                let mut f = f.clone();
                f.attrs = Vec::new();
                Some(f)
            }
        })
        .collect();
    let input_field = input_field?;

    // Generate the code for creating the original proc from the dyn proc
    let assign_fields = other_fields
        .iter()
        .map(|field| {
            let fi = field.ident.as_ref().unwrap();
            quote! {#fi: self.#fi,}
        })
        .collect::<proc_macro2::TokenStream>();

    // Create a clone of the procedure with ident <Proc-Name>Dyn.
    // The clone copies all fields from the original one apart from the input one.
    let mut dyn_proc = derive_input.clone();
    let dyn_proc_ident = syn::Ident::new(&format!("{}Dyn", derive_input.ident), derive_input.ident.span());
    dyn_proc.ident = dyn_proc_ident.clone();

    // Assign only the non-input fields.
    let fields = match dyn_proc.data {
        Data::Struct(DataStruct {
            fields: Fields::Named(ref mut fields),
            ..
        }) => fields,
        _ => return None,
    };
    fields.named = other_fields;

    let original_proc_ident = derive_input.ident.clone();
    let input_field_ident = input_field.ident.unwrap();
    let in_type = input_field.ty;
    let (impl_generics, ty_generics, where_clause) = dyn_proc.generics.split_for_impl();

    let gen = quote! {

        #[derive(Clone)]
        #dyn_proc

        impl #impl_generics ExecProc for #dyn_proc_ident #ty_generics #where_clause {
            type InData = #in_type;
            type OutData = <#original_proc_ident as ExecProc>::OutData;

            fn exec<X: ProcExecutor>(self, executor: &mut X, input: Self::InData) -> Result<Self::OutData, anyhow::Error> {
                let proc = #original_proc_ident {#assign_fields #input_field_ident: input};
                proc.exec(executor, ())
            }
        }
    };
    impls.push(gen);
    Some(dyn_proc_ident)
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
    dyn_proc_ident: &Option<Ident>,
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
            Location::Source,
            proc_ident,
            dyn_proc_ident,
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
            Location::Target,
            proc_ident,
            dyn_proc_ident,
            field_ident,
            field_type,
            generics.clone(),
        );
    }
}

enum Location {
    Source,
    Target,
}

fn impl_get_location(
    impls: &mut Vec<proc_macro2::TokenStream>,
    loc: Location,
    proc_ident: &Ident,
    dyn_proc_ident: &Option<Ident>,
    field_ident: &Ident,
    field_type: &Type,
    generics: Generics,
) {
    let (trait_name, fn_name, return_type) = match loc {
        Location::Source => (quote! {GetSourceVault}, quote! {get_source}, quote! {Location}),
        Location::Target => (
            quote! {GetTargetVault},
            quote! {get_target},
            quote! {(Location, RecordHint)},
        ),
    };

    let location = quote! {self.#field_ident.#fn_name()};

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

    let mut idents = vec![proc_ident];

    if let Some(dyn_proc) = dyn_proc_ident {
        idents.push(dyn_proc);
    }

    for ident in idents {
        impls.push(quote! {
            impl #impl_generics #trait_name for #ident #ty_generics #gen_where_clause {
                fn #fn_name(&self) -> #return_type {
                    #location
                }
            }
        })
    }
}

// `proc_fn` macro logic

pub fn impl_exec_proc(item_impl: ItemImpl) -> proc_macro2::TokenStream {
    let panic_msg =
        "The proc_fn macro can only applied for implementation blocks of the traits `Generate`, `Process` or `Sink`.";

    let segment = item_impl
        .trait_
        .and_then(|t| t.1.segments.last().cloned())
        .expect(panic_msg);

    let gen_exec_fn = generate_fn_body(&segment);
    let out_type = item_impl
        .items
        .iter()
        .find_map(|i| match i {
            ImplItem::Type(ImplItemType { ident, ty, .. }) if ident == "OutData" => Some(ty),
            _ => None,
        })
        .expect("Missing associated type OutData");
    let self_type = item_impl.self_ty;
    let (impl_generics, ty_generics, where_clause) = item_impl.generics.split_for_impl();

    quote! {
        impl #impl_generics ExecProc for #self_type #ty_generics #where_clause {
            type InData = ();
            type OutData = #out_type;

            fn exec<X: ProcExecutor>(self, executor: &mut X, input: Self::InData) -> Result<Self::OutData, anyhow::Error> {
                #gen_exec_fn
            }
        }
    }
}

fn generate_fn_body(segment: &PathSegment) -> proc_macro2::TokenStream {
    match format!("{}", segment.ident).as_str() {
        "Generate" => {
            quote! {
                let (location_1, hint) = self.get_target();
                let ProcOutput {
                    write_vault,
                    return_value,
                } = <Self as Generate>::generate(self)?;
                executor.write_to_vault(location_1, hint, write_vault)?;
                Ok(return_value)
            }
        }
        "Process" => {
            quote! {
                let location_0 = self.get_source();
                let (location_1, hint) = self.get_target();
                let f = move |(), guard| <Self as Process>::process(self, guard);
                let res = executor.exec_proc(
                    location_0,
                    location_1,
                    hint,
                    f,
                    ()
                );

                res
            }
        }
        "Sink" => {
            quote! {
                let location_0 = self.get_source();
                let f = move |(), guard| <Self as Sink>::sink(self, guard);
                let res = executor.get_guard(location_0, f, ());
                res
            }
        }
        _ => panic!(),
    }
}
