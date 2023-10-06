use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::parse_macro_input;

#[proc_macro_attribute]
pub fn elevate_code(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as syn::ItemFn);
    let mut inner = input.clone();
    let fn_ident = &input.sig.ident;
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
    let type_list = input
        .sig
        .inputs
        .iter()
        .map(|arg| match arg {
            syn::FnArg::Receiver(_) => todo!(),
            syn::FnArg::Typed(typed) => {
                let ty = &typed.ty;
                quote!(#ty)
            }
        })
        .collect::<Vec<_>>();

    inner.sig.ident = format_ident!("_{}", fn_name);
    let inner_name = &inner.sig.ident;

    let (call, serialization) = if type_list.is_empty() {
        (
            quote! {
                #fn_ident();
                std::process::exit(0);
            },
            quote! {
                Some(String::new())
            },
        )
    } else {
        (
            quote! {
                let (#(#args),*,) : (#(#type_list),*,) = _elevate_code::serde_json::from_str(&payload).map_err(|err| format!("{err}")).unwrap();
                #fn_ident(
                    #(#args),*
                );
                std::process::exit(0);
            },
            quote! {
                _elevate_code::serde_json::to_string(
                    &(#(&#args),*,)
                ).map_err(|err| format!("{err}")).ok()
            },
        )
    };

    let decoration = quote! {
        const _: () = {
            extern crate elevate_code as _elevate_code;

            struct T;

            #[_elevate_code::ctor::ctor]
            fn init() {
                let id: &str = #fn_name;

                let cmd_line = _elevate_code::ElevateToken::from_command_line();

                match _elevate_code::ElevateToken::from_command_line() {
                    Some(_elevate_code::ElevateToken::Execute { task_id, payload }) if id == task_id => {
                        #call
                    }
                    _ => {},
                }
            }
        };

        #sig {
            extern crate elevate_code as _elevate_code;

            #inner

            let id: &str = #fn_name;

            if _elevate_code::is_elevated() {
                return #inner_name(#(#args),*);
            }

            if let Some(json) = #serialization {
                let token = _elevate_code::ElevateToken::Execute {
                    task_id: id.to_string(),
                    payload: json,
                };
                _elevate_code::create_process(&[&token.to_string()], |pid| {
                    match _elevate_code::GLOBAL_CLIENT.request(_elevate_code::ElevationRequest::new(pid)) {
                        Ok(_) => _elevate_code::ProcessControlFlow::ResumeMainThread,
                        Err(err) => _elevate_code::ProcessControlFlow::Terminate,
                    }
                });
            } else {
                panic!("Error on serializing arguments")
            }
        }
    };

    decoration.into()
}
