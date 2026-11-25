// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    string::ToString as _,
    vec,
    vec::Vec,
};

#[cfg(feature = "codegen")]
pub use ::{prettyplease, proc_macro2, quote, syn};
use fs_err as fs;
use proc_macro2::TokenStream;
use quote::{ToTokens as _, format_ident, quote};
use syn::visit_mut::{self, VisitMut};

pub const GEN_TESTS_DIR: &str = "src/gen/tests";

#[derive(Clone, Copy)]
pub struct AssertImplConfig {
    pub exclude: &'static [&'static str],
    pub not_send: &'static [&'static str],
    pub not_sync: &'static [&'static str],
    pub not_unpin: &'static [&'static str],
    pub not_unwind_safe: &'static [&'static str],
    pub not_ref_unwind_safe: &'static [&'static str],
}

#[must_use]
pub fn gen_assert_impl(crate_root: &Path, config: AssertImplConfig) -> (PathBuf, TokenStream) {
    let out_dir = &crate_root.join(GEN_TESTS_DIR);
    fs::create_dir_all(out_dir).unwrap();

    let files = crate::git::ls_files(crate_root.join("src"), &["*.rs"]);
    let mut tokens = quote! {};
    let mut visited_types = HashSet::new();
    for (file_name, path) in &files {
        // Assertions are only needed for the library's public APIs.
        if file_name == "main.rs" || file_name.starts_with("bin/") {
            continue;
        }

        let s = fs::read_to_string(path).unwrap();
        let ast = syn::parse_file(&s).unwrap();

        let module = if file_name == "lib.rs" {
            vec![]
        } else {
            let name =
                format_ident!("{}", Path::new(file_name).file_stem().unwrap().to_str().unwrap());
            vec![name.into()]
        };

        // TODO: assert impl trait returned from public functions
        visit_items(module, ast, |item, module| match item {
            syn::Item::Struct(syn::ItemStruct { vis, ident, generics, .. })
            | syn::Item::Enum(syn::ItemEnum { vis, ident, generics, .. })
            | syn::Item::Union(syn::ItemUnion { vis, ident, generics, .. })
            | syn::Item::Type(syn::ItemType { vis, ident, generics, .. })
                if matches!(vis, syn::Visibility::Public(..)) =>
            {
                let path_string = quote! { #(#module::)* #ident }.to_string().replace(' ', "");
                visited_types.insert(path_string.clone());
                if config.exclude.contains(&path_string.as_str()) {
                    return;
                }

                let type_params = generics.type_params().count();
                assert_eq!(
                    generics.const_params().count(),
                    0,
                    "gen_assert_impl doesn't support const generics yet; skipped `{}`",
                    path_string
                );

                let ty = quote! { crate:: #(#module::)* #ident };
                let mut assert_value = |args: &[TokenStream], traits: &TokenStream| {
                    let args = if generics.params.is_empty() {
                        quote! {}
                    } else {
                        let lifetimes = generics.lifetimes().map(|_| quote! { '_ });
                        let args = lifetimes.chain(args.iter().cloned());
                        quote! { <#(#args),*> }
                    };
                    tokens.extend(quote! { test_helper::assert_value!(#ty #args: #traits); });
                };
                let implements = |exceptions: &[&str]| !exceptions.contains(&path_string.as_str());
                let send = implements(config.not_send);
                let sync = implements(config.not_sync);
                // Each marker tests its own trait. NotSend and NotSync also test that
                // the other trait is still implemented independently.
                let traits = [
                    ("Send", send, sync.then(|| quote! { Sync })),
                    ("Sync", sync, send.then(|| quote! { Send })),
                    ("Unpin", implements(config.not_unpin), None),
                    ("UnwindSafe", implements(config.not_unwind_safe), None),
                    ("RefUnwindSafe", implements(config.not_ref_unwind_safe), None),
                ];
                let baseline = traits.iter().map(|(name, positive, _)| {
                    let ident = format_ident!("{}", name);
                    if *positive {
                        quote! { #ident }
                    } else {
                        quote! { !#ident }
                    }
                });
                let unit = quote! { () };
                let mut args = vec![unit.clone(); type_params];
                assert_value(&args, &quote! { #(#baseline)&* });

                if type_params == 0 {
                    return;
                }
                for (name, positive, other_trait) in traits {
                    let ident = format_ident!("{}", name);
                    let mut checks = vec![];
                    if positive {
                        checks.push(quote! { !#ident });
                    }
                    checks.extend(other_trait);
                    if checks.is_empty() {
                        continue;
                    }
                    let checks = quote! { #(#checks)&* };
                    let marker = format_ident!("Not{}", name);
                    let marker = quote! { test_helper::marker::#marker };
                    assert_value(&vec![marker.clone(); type_params], &checks);
                    if type_params > 1 {
                        // A missing bound on one parameter can be masked by another.
                        for i in 0..type_params {
                            args[i] = marker.clone();
                            assert_value(&args, &checks);
                            args[i] = unit.clone();
                        }
                    }
                }
            }
            _ => {}
        });
    }

    for (list, name) in &[
        (config.exclude, "AssertImplConfig::exclude"),
        (config.not_send, "AssertImplConfig::not_send"),
        (config.not_sync, "AssertImplConfig::not_sync"),
        (config.not_unpin, "AssertImplConfig::not_unpin"),
        (config.not_unwind_safe, "AssertImplConfig::not_unwind_safe"),
        (config.not_ref_unwind_safe, "AssertImplConfig::not_ref_unwind_safe"),
    ] {
        for &ty in *list {
            assert!(
                visited_types.contains(ty),
                "unknown type `{}` specified in {} field",
                ty,
                name
            );
        }
    }

    (out_dir.join("assert_impl.rs"), tokens)
}

#[derive(Clone, Copy)]
pub struct TrackSizeConfig {
    pub exclude: &'static [&'static str],
}

#[must_use]
pub fn gen_track_size(crate_root: &Path, config: TrackSizeConfig) -> (PathBuf, TokenStream) {
    let out_dir = &crate_root.join(GEN_TESTS_DIR);
    fs::create_dir_all(out_dir).unwrap();

    let files = crate::git::ls_files(crate_root.join("src"), &["*.rs"]);
    let mut tokens = quote! {};
    let mut visited_types = HashSet::new();
    for (file_name, path) in &files {
        // Assertions are only needed for the library's public APIs.
        if file_name == "main.rs" || file_name.starts_with("bin/") {
            continue;
        }

        let s = fs::read_to_string(path).unwrap();
        let ast = syn::parse_file(&s).unwrap();

        let module = if file_name == "lib.rs" {
            vec![]
        } else {
            let name =
                format_ident!("{}", Path::new(file_name).file_stem().unwrap().to_string_lossy());
            vec![name.into()]
        };

        // Item:Type is ignored since the size of it cannot be controlled by us.
        // TODO: assert impl trait returned from public functions
        visit_items(module, ast, |item, module| match item {
            syn::Item::Struct(syn::ItemStruct { vis, ident, generics, .. })
            | syn::Item::Enum(syn::ItemEnum { vis, ident, generics, .. })
            | syn::Item::Union(syn::ItemUnion { vis, ident, generics, .. })
                if matches!(vis, syn::Visibility::Public(..)) =>
            {
                let path_string = quote! { #(#module::)* #ident }.to_string().replace(' ', "");
                visited_types.insert(path_string.clone());
                if config.exclude.contains(&path_string.as_str()) {
                    return;
                }

                let has_generics = generics.type_params().count() != 0;
                let has_lifetimes = generics.lifetimes().count() != 0;
                assert_eq!(
                    generics.const_params().count(),
                    0,
                    "gen_track_size doesn't support const generics yet; skipped `{}`",
                    path_string
                );

                let lt = generics.lifetimes().map(|_| quote! { '_ });
                if has_generics {
                    let lt = quote! { #(#lt,)* };
                    let unit = generics.type_params().map(|_| quote! { () });
                    let unit_generics = quote! { <#lt #(#unit),*> };
                    tokens.extend(quote! {
                        write_size::<crate:: #(#module::)* #ident #unit_generics>(&mut out);
                    });
                } else {
                    let lt = if has_lifetimes {
                        quote! { <#(#lt),*> }
                    } else {
                        quote! {}
                    };
                    tokens.extend(quote! {
                        write_size::<crate:: #(#module::)* #ident #lt>(&mut out);
                    });
                }
            }
            _ => {}
        });
    }

    for &ty in config.exclude {
        assert!(
            visited_types.contains(ty),
            "unknown type `{}` specified in AssertImplConfig::exclude field",
            ty
        );
    }

    let mut out = quote! {
        #![allow(
            dead_code,
            clippy::std_instead_of_alloc,
            clippy::std_instead_of_core,
        )]
        use std::{fmt::Write as _, path::Path, string::String};
        fn write_size<T>(out: &mut String) {
            let _ = writeln!(
                out,
                "{}: {}",
                std::any::type_name::<T>(),
                std::mem::size_of::<T>()
            );
        }
    };
    out.extend(quote! {
        /// Test the size of public types. This is not intended to keep a specific size and is intended to
        /// be used only as a help in optimization.
        ///
        /// Ignore non-64-bit targets due to usize/ptr size, ignore Miri/cargo-careful as we set
        /// -Z randomize-layout for them, and ignore old rustc as any::type_name output and size
        /// optimization may differ between compiler versions.
        #[cfg_attr(any(not(target_pointer_width = "64"), miri, careful), ignore)]
        #[test]
        fn track_size() {
            if !build_context::RUSTC_NIGHTLY {
                return;
            }
            let mut out = String::new();
            #tokens
            test_helper::git::assert_diff(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("src/gen/tests/track_size.txt"),
                out,
            );
        }
    });
    (out_dir.join("track_size.rs"), out)
}

pub fn visit_items(
    module: Vec<syn::PathSegment>,
    mut ast: syn::File,
    f: impl FnMut(&mut syn::Item, &[syn::PathSegment]),
) {
    #[must_use]
    struct ItemVisitor<F> {
        module: Vec<syn::PathSegment>,
        f: F,
    }
    impl<F> VisitMut for ItemVisitor<F>
    where
        F: FnMut(&mut syn::Item, &[syn::PathSegment]),
    {
        fn visit_item_mut(&mut self, item: &mut syn::Item) {
            match item {
                syn::Item::Mod(item) => {
                    self.module.push(item.ident.clone().into());
                    visit_mut::visit_item_mod_mut(self, item);
                    self.module.pop();
                }
                syn::Item::Macro(item) => {
                    if let Ok(mut file) = syn::parse2::<syn::File>(item.mac.tokens.clone()) {
                        visit_mut::visit_file_mut(self, &mut file);
                        item.mac.tokens = file.into_token_stream();
                    }
                    visit_mut::visit_item_macro_mut(self, item);
                }
                _ => {
                    (self.f)(item, &self.module);
                    visit_mut::visit_item_mut(self, item);
                }
            }
        }
    }

    ItemVisitor { module, f }.visit_file_mut(&mut ast);
}

pub mod file {
    use std::{eprintln, format, path::Path, string::String, sync::OnceLock, vec, vec::Vec};

    use fs_err as fs;
    use proc_macro2::TokenStream;

    #[must_use]
    #[track_caller]
    pub fn header(function_name: &str, bin_name: &str) -> String {
        // rust-analyzer does not respect outer attribute (#[rustfmt::skip]) on
        // a module without a body and unstable ignore option in .rustfmt.toml.
        // https://github.com/rust-lang/rust-analyzer/issues/10826
        // So use inner attribute under cfg(rustfmt).
        format!(
            "// SPDX-License-Identifier: Apache-2.0 OR MIT
// This file is @generated by {bin_name}
// ({function_name} function at {file}).
// It is not intended for manual editing.\n
#![cfg_attr(rustfmt, rustfmt::skip)]
",
            file = std::panic::Location::caller().file()
        )
    }

    #[allow(clippy::needless_pass_by_value)]
    #[track_caller]
    pub fn write(
        function_name: &str,
        bin_name: &str,
        workspace_root: &Path,
        path: impl AsRef<Path>,
        contents: TokenStream,
    ) {
        write_raw(function_name, bin_name, workspace_root, path.as_ref(), format_tokens(&contents));
    }

    #[track_caller]
    pub fn write_raw(
        function_name: &str,
        bin_name: &str,
        workspace_root: &Path,
        path: &Path,
        contents: impl AsRef<[u8]>,
    ) {
        static LINGUIST_GENERATED: OnceLock<Vec<globset::GlobMatcher>> = OnceLock::new();
        let linguist_generated = LINGUIST_GENERATED.get_or_init(|| {
            let mut linguist_generated = vec![];
            if let Ok(gitattributes) = fs::read_to_string(workspace_root.join(".gitattributes")) {
                for line in gitattributes.lines() {
                    if line.contains("linguist-generated") {
                        linguist_generated.push(
                            globset::Glob::new(line.split_once([' ', '\t']).unwrap().0)
                                .unwrap()
                                .compile_matcher(),
                        );
                    }
                }
            }
            linguist_generated
        });
        let p = path.strip_prefix(workspace_root).unwrap();
        if !linguist_generated.iter().any(|m| m.is_match(p)) {
            eprintln!("warning: you may want to mark {} linguist-generated", p.display());
        }

        let mut out = header(function_name, bin_name).into_bytes();
        out.extend_from_slice(contents.as_ref());
        while out.ends_with(b"\n\n") {
            out.pop();
        }
        if path.is_file() && fs::read(path).unwrap() == out {
            return;
        }
        fs::write(path, out).unwrap();
        eprintln!("updated {}", p.display());
    }

    #[track_caller]
    fn format_tokens(contents: &TokenStream) -> String {
        prettyplease::unparse(
            &syn::parse2(contents.clone())
                .unwrap_or_else(|e| panic!("{} in:\n---\n{}\n---", e, contents)),
        )
    }
}
