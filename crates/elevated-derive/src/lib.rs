use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::parse_macro_input;

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

    let mut inner = input.clone();
    inner.sig.ident = format_ident!("_{}", fn_name);
    let inner_name = &inner.sig.ident;

    let serialization = if type_list.is_empty() {
        quote! {
            Some(String::new())
        }
    } else {
        quote! {
            _elevated::serde_json::to_string(
                &(#(&#args),*,)
            ).map_err(|err| format!("{err}")).ok()
        }
    };

    let decoration = quote! {
        #sig {
            extern crate elevated as _elevated;

            #inner

            let id: &str = #fn_name;

            if _elevated::is_elevated() {
                return #inner_name(#(#args),*);
            }

            if let Some(json) = #serialization {
                let (p, mut c) = _elevated::channel::InterProcessChannelPeer::new();
                let ret = _elevated::create_process(|pid| {
                    match _elevated::GLOBAL_CLIENT.request(_elevated::ElevationRequest::new(pid)) {
                        Ok(_) => _elevated::ProcessControlFlow::ResumeMainThread,
                        Err(err) => _elevated::ProcessControlFlow::Terminate,
                    }
                }).unwrap();
                if matches!(ret, _elevated::ForkResult::Child) {
                    #inner_name(#(#args),*);
                    // todo 返回值。
                    c.send("hello".as_bytes());
                    std::process::exit(0);
                } else {
                    // 等待调用结果。
                    p.recv();
                }
            } else {
                panic!("Error on serializing arguments")
            }
        }
    };

    decoration.into()
}
