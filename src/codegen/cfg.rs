// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::{path::PathBuf, vec::Vec};

use proc_macro2::{TokenStream, TokenTree};
use quote::quote;
use syn::{
    Attribute, Expr, Lit, Meta, Token, parse::Parser as _, parse_quote, punctuated::Punctuated,
};

// Visit attributes in expansion order, recording when each nested attribute applies.
fn visit(
    meta: &Meta,
    conditions: &mut Vec<TokenStream>,
    f: &mut impl FnMut(&Meta, &[TokenStream]),
) {
    if let Meta::List(list) = meta {
        if list.path.is_ident("cfg_attr") {
            // Leave the predicate as tokens, including newer forms such as cfg(true).
            let mut tokens = list.tokens.clone().into_iter();
            let predicate: TokenStream = tokens
                .by_ref()
                .take_while(|t| !matches!(t, TokenTree::Punct(p) if p.as_char() == ','))
                .collect();
            let nested =
                Punctuated::<Meta, Token![,]>::parse_terminated.parse2(tokens.collect()).unwrap();
            conditions.push(predicate);
            for meta in &nested {
                visit(meta, conditions, f);
            }
            conditions.pop();
            return;
        }
    }
    f(meta, conditions);
}

// Keep predicates nested: a toolchain might only accept an inner predicate when
// the outer condition holds (for example, a nightly-only cfg).
fn conditional(conditions: &[TokenStream], meta: TokenStream) -> TokenStream {
    conditions.iter().rev().fold(meta, |meta, p| quote!(cfg_attr(#p, #meta)))
}

pub(super) fn cfg_attrs(attrs: &[Attribute]) -> Vec<Attribute> {
    let mut cfgs = Vec::new();
    for attr in attrs {
        visit(&attr.meta, &mut Vec::new(), &mut |meta, conditions| {
            if meta.path().is_ident("cfg") {
                let meta = conditional(conditions, quote!(#meta));
                cfgs.push(parse_quote!(#[#meta]));
            }
        });
    }
    cfgs
}

pub(super) fn module_paths(attrs: &[Attribute]) -> Vec<(Option<PathBuf>, Vec<Attribute>)> {
    let mut paths = Vec::new();
    for attr in attrs {
        visit(&attr.meta, &mut Vec::new(), &mut |meta, conditions| {
            let value = match meta {
                Meta::NameValue(nv) if nv.path.is_ident("path") => &nv.value,
                _ => return,
            };
            if let Expr::Lit(syn::ExprLit { lit: Lit::Str(path), .. }) = value {
                paths.push((Some(PathBuf::from(path.value())), conditions.to_vec()));
            }
        });
    }
    paths.push((None, Vec::new())); // The ordinary path if no path attribute applies.

    // rustc uses the first active path attribute in source order.
    let mut alternatives = Vec::new();
    let mut previous = Vec::new();
    for (path, conditions) in paths {
        let mut cfgs: Vec<_> = previous.iter().map(|p| parse_quote!(#[#p])).collect();
        cfgs.extend(conditions.iter().map(|p| -> Attribute { parse_quote!(#[cfg(#p)]) }));
        alternatives.push((path, cfgs));
        if let Some((last, parents)) = conditions.split_last() {
            previous.push(conditional(parents, quote!(cfg(not(#last)))));
        } else {
            break;
        }
    }
    alternatives
}
