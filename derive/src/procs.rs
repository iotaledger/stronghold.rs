// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use quote::quote;
use syn::{
    punctuated::Punctuated, token::Comma, Data, DataStruct, DeriveInput, Field, Fields, ImplGenerics, ImplItem,
    ImplItemType, ItemImpl, PathSegment,
};

pub fn derive_source_target(derive_input: DeriveInput) -> proc_macro2::TokenStream {
    let proc_ident = derive_input.ident.clone();
    let (impl_generics, ty_generics, where_clause) = derive_input.generics.split_for_impl();
    let mut impls = Vec::new();

    let for_self = quote! {#proc_ident #ty_generics #where_clause};

    let fields = match derive_input.data.clone() {
        Data::Struct(DataStruct {
            fields: Fields::Named(f),
            ..
        }) => Some(f.named),
        _ => None,
    };

    if let Some(fields) = fields.as_ref() {
        let for_other = impl_no_input(&derive_input, fields).map(|(impl_, other_ident)| {
            impls.push(impl_);
            quote! {#other_ident #ty_generics #where_clause}
        });

        for field in fields {
            if let Some(impl_) = impl_by_field(field, &impl_generics, &for_self, &for_other) {
                impls.push(impl_)
            }
        }
    }
    impls.into_iter().collect()
}

pub fn impl_no_input(
    derive_input: &DeriveInput,
    fields: &Punctuated<Field, Comma>,
) -> Option<(proc_macro2::TokenStream, syn::Ident)> {
    let mut input_field = None;
    let other_fields: Punctuated<Field, Comma> = fields
        .clone()
        .into_iter()
        .filter_map(|mut f| {
            let is_no_input = !f.attrs.iter().any(|a| match a.path.segments.last() {
                Some(seg) if seg.ident == "input" => {
                    input_field = Some(f.clone());
                    true
                }
                _ => false,
            });
            f.attrs = Vec::new();
            // panic!("{}, {:?}", is_no_input, f);
            is_no_input.then(|| f)
        })
        .collect();

    input_field.map(|field|  {
        // panic!("{:?}, \n\n{:?}", fields, other_fields);
        let mut other = derive_input.clone();
        let (impl_generics, _, where_clause) = other.generics.split_for_impl();
        let other_name = format!("{}Dyn", derive_input.ident);
        let other_ident = syn::Ident::new(&other_name, derive_input.ident.span());
        other.ident = other_ident.clone();
        other.attrs = Vec::new();
        if let Data::Struct(DataStruct {fields: Fields::Named(ref mut fields), ..}) = other.data {
            fields.named = other_fields.clone()
        }

        let in_type = field.ty;
        let assign_fields = other_fields.into_iter().map(|field| {
            let fi = field.ident.unwrap();
            quote! {#fi: self.#fi,}
        }).collect::<proc_macro2::TokenStream>();

        let proc_ident = derive_input.ident.clone();
        let field_ident = field.ident.unwrap();
        let gen = quote! {
            #[derive(Clone)]
            #other

            impl #impl_generics ExecProc for #other_ident #where_clause {
                type InData = #in_type;
                type OutData = <#proc_ident as ExecProc>::OutData;

                fn exec<X: ProcExecutor>(self, executor: &mut X, input: Self::InData) -> Result<Self::OutData, anyhow::Error> {
                    let proc = #proc_ident {#assign_fields #field_ident: input};
                    proc.exec(executor, ())
                }
            }

            impl #impl_generics BuildProc<Self> for #other_ident #where_clause {
                fn build(self) -> ComplexProc<Self> {
                    ComplexProc {inner: self}
                }
            }

        };
        // panic!("{}", gen);
        (gen, other_ident)
    })
}

fn impl_by_field(
    field: &Field,
    impl_generics: &ImplGenerics,
    for_self: &proc_macro2::TokenStream,
    for_other: &Option<proc_macro2::TokenStream>,
) -> Option<proc_macro2::TokenStream> {
    let field_ident = field.ident.clone();
    if field
        .attrs
        .iter()
        .any(|attr| attr.path.segments.last().unwrap().ident == "source_location")
    {
        let impl_for_other = for_other.as_ref().map(|for_other| {
            quote! {
                impl #impl_generics GetSourceVault for #for_other {
                    fn get_source(&self) -> Location {
                        self.#field_ident.clone()
                    }
                }
            }
        });
        Some(quote! {
            impl #impl_generics GetSourceVault for #for_self {
                fn get_source(&self) -> Location {
                    self.#field_ident.clone()
                }
            }
            #impl_for_other
        })
    } else if field
        .attrs
        .iter()
        .any(|attr| attr.path.segments.last().unwrap().ident == "target_location")
    {
        let impl_for_other = for_other.as_ref().map(|for_other| {
            quote! {
                impl #impl_generics GetTargetVault for #for_other {
                    fn get_target(&self) -> (Location, RecordHint) {
                        self.#field_ident.clone()
                    }
                }
            }
        });
        Some(quote! {
            impl #impl_generics GetTargetVault for #for_self {
                fn get_target(&self) -> (Location, RecordHint) {
                    self.#field_ident.clone()
                }
            }
            #impl_for_other
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

    let segment = item_impl
        .trait_
        .and_then(|t| t.1.segments.last().cloned())
        .expect(panic_msg);

    let out_type = item_impl
        .items
        .iter()
        .find_map(|i| match i {
            ImplItem::Type(ImplItemType { ident, ty, .. }) if ident == "OutData" => Some(ty),
            _ => None,
        })
        .expect("Missing associated type OutData");

    let gen_exec_fn = generate_fn_body(&segment);
    quote! {
        impl #impl_generics ExecProc for #self_type #where_clause {
            type InData = ();
            type OutData = #out_type;

            fn exec<X: ProcExecutor>(self, executor: &mut X, input: Self::InData) -> Result<Self::OutData, anyhow::Error> {
                #gen_exec_fn
            }
        }
        impl #impl_generics BuildProc<Self> for #self_type #where_clause {
            fn build(self) -> ComplexProc<Self> {
                ComplexProc {inner: self}
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
