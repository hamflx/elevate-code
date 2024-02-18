use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::parse_macro_input;

#[proc_macro_attribute]
pub fn main(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let mut inner_fn = parse_macro_input!(input as syn::ItemFn);
    let wrapper_fn = inner_fn.clone();
    let wrapper_sig = &wrapper_fn.sig;
    inner_fn.sig.ident = format_ident!("_{}", wrapper_sig.ident);
    let inner_ident = &inner_fn.sig.ident;
    let args = wrapper_sig.inputs.iter().map(|arg| match arg {
        syn::FnArg::Receiver(_) => unimplemented!(),
        syn::FnArg::Typed(typed) => match typed.pat.as_ref() {
            syn::Pat::Ident(ident) => ident.ident.clone(),
            _ => unimplemented!(),
        },
    });

    let decoration = quote! {
        #wrapper_sig {
            extern crate elevated as _elevated;

            #inner_fn

            _elevated::execute_elevation_and_tasks();

            #inner_ident(#(#args),*)
        }
    };

    decoration.into()
}

#[proc_macro_attribute]
pub fn elevated(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as syn::ItemFn);
    let fn_name = input.sig.ident.to_string();
    let sig = &input.sig;
    let args = input
        .sig
        .inputs
        .iter()
        .map(|arg| match arg {
            syn::FnArg::Receiver(_) => format_ident!("self"),
            syn::FnArg::Typed(typed) => match typed.pat.as_ref() {
                syn::Pat::Ident(ident) => ident.ident.clone(),
                _ => todo!(),
            },
        })
        .collect::<Vec<_>>();

    let mut inner = input.clone();
    inner.sig.ident = format_ident!("_{}", fn_name);
    let inner_name = &inner.sig.ident;

    let arg_types = input.sig.inputs.iter().map(|arg| match arg {
        syn::FnArg::Receiver(_) => unimplemented!(),
        syn::FnArg::Typed(typed) => &typed.ty,
    });

    let decoration = quote! {
        #sig {
            extern crate elevated as _elevated;

            #inner

            fn caller(arg: String) -> String {
                let (#(#args,)*): (#(#arg_types,)*) = _elevated::serde_json::from_str(&arg).unwrap();
                let ret = #inner_name(#(#args),*);
                _elevated::serde_json::to_string(&ret).unwrap()
            }

            let id: &str = #fn_name;

            if _elevated::is_elevated() {
                return #inner_name(#(#args),*);
            }

            let args = _elevated::serde_json::to_string(&(#(#args,)*)).unwrap();
            _elevated::spawn_task(caller, args).unwrap()
        }
    };

    decoration.into()
}
