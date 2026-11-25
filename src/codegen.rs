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
    let mut use_generics_helpers = false;
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
                let has_lifetimes = generics.lifetimes().count() != 0;
                assert_eq!(
                    generics.const_params().count(),
                    0,
                    "gen_assert_impl doesn't support const generics yet; skipped `{}`",
                    path_string
                );

                let lt = generics.lifetimes().map(|_| quote! { '_ });
                if type_params != 0 {
                    let lt = quote! { #(#lt,)* };
                    use_generics_helpers = true;
                    let ty = quote! { crate:: #(#module::)* #ident };
                    let unit = quote! { () };
                    let units = (0..type_params).map(|_| &unit);
                    let baseline = quote! { #ty <#lt #(#units),*> };
                    let with_marker = |marker: TokenStream| {
                        let all = (0..type_params).map(|_| &marker);
                        let mut types = vec![quote! { #ty <#lt #(#all),*> }];
                        // With several parameters, the all-marker case alone can hide
                        // a missing bound when another parameter still requires the trait.
                        if type_params > 1 {
                            for index in 0..type_params {
                                let args = (0..type_params)
                                    .map(|i| if i == index { &marker } else { &unit });
                                types.push(quote! { #ty <#lt #(#args),*> });
                            }
                        }
                        types
                    };
                    let not_send = with_marker(quote! { NotSend });
                    let not_sync = with_marker(quote! { NotSync });
                    let not_unpin = with_marker(quote! { NotUnpin });
                    let not_unwind_safe = with_marker(quote! { NotUnwindSafe });
                    let not_ref_unwind_safe = with_marker(quote! { NotRefUnwindSafe });
                    if config.not_send.contains(&path_string.as_str()) {
                        tokens.extend(quote! {
                            assert_not_send!(#baseline);
                        });
                    } else {
                        tokens.extend(quote! {
                            assert_send::<#baseline>();
                            #(assert_send::<#not_sync>();)*
                            #(assert_not_send!(#not_send);)*
                        });
                    }
                    if config.not_sync.contains(&path_string.as_str()) {
                        tokens.extend(quote! {
                            assert_not_sync!(#baseline);
                        });
                    } else {
                        tokens.extend(quote! {
                            assert_sync::<#baseline>();
                            #(assert_sync::<#not_send>();)*
                            #(assert_not_sync!(#not_sync);)*
                        });
                    }
                    if config.not_unpin.contains(&path_string.as_str()) {
                        tokens.extend(quote! {
                            assert_not_unpin!(#baseline);
                        });
                    } else {
                        tokens.extend(quote! {
                            assert_unpin::<#baseline>();
                            #(assert_not_unpin!(#not_unpin);)*
                        });
                    }
                    if config.not_unwind_safe.contains(&path_string.as_str()) {
                        tokens.extend(quote! {
                            assert_not_unwind_safe!(#baseline);
                        });
                    } else {
                        tokens.extend(quote! {
                            assert_unwind_safe::<#baseline>();
                            #(assert_not_unwind_safe!(#not_unwind_safe);)*
                        });
                    }
                    if config.not_ref_unwind_safe.contains(&path_string.as_str()) {
                        tokens.extend(quote! {
                            assert_not_ref_unwind_safe!(#baseline);
                        });
                    } else {
                        tokens.extend(quote! {
                            assert_ref_unwind_safe::<#baseline>();
                            #(assert_not_ref_unwind_safe!(#not_ref_unwind_safe);)*
                        });
                    }
                } else {
                    let lt = if has_lifetimes {
                        quote! { <#(#lt),*> }
                    } else {
                        quote! {}
                    };
                    if config.not_send.contains(&path_string.as_str()) {
                        tokens.extend(quote! {
                            assert_not_send!(crate:: #(#module::)* #ident #lt);
                        });
                    } else {
                        tokens.extend(quote! {
                            assert_send::<crate:: #(#module::)* #ident #lt>();
                        });
                    }
                    if config.not_sync.contains(&path_string.as_str()) {
                        tokens.extend(quote! {
                            assert_not_sync!(crate:: #(#module::)* #ident #lt);
                        });
                    } else {
                        tokens.extend(quote! {
                            assert_sync::<crate:: #(#module::)* #ident #lt>();
                        });
                    }
                    if config.not_unpin.contains(&path_string.as_str()) {
                        tokens.extend(quote! {
                            assert_not_unpin!(crate:: #(#module::)* #ident #lt);
                        });
                    } else {
                        tokens.extend(quote! {
                            assert_unpin::<crate:: #(#module::)* #ident #lt>();
                        });
                    }
                    if config.not_unwind_safe.contains(&path_string.as_str()) {
                        tokens.extend(quote! {
                            assert_not_unwind_safe!(crate:: #(#module::)* #ident #lt);
                        });
                    } else {
                        tokens.extend(quote! {
                            assert_unwind_safe::<crate:: #(#module::)* #ident #lt>();
                        });
                    }
                    if config.not_ref_unwind_safe.contains(&path_string.as_str()) {
                        tokens.extend(quote! {
                            assert_not_ref_unwind_safe!(crate:: #(#module::)* #ident #lt);
                        });
                    } else {
                        tokens.extend(quote! {
                            assert_ref_unwind_safe::<crate:: #(#module::)* #ident #lt>();
                        });
                    }
                }
            }
            _ => {}
        });
    }

    let mut use_macros = use_generics_helpers;
    for (list, name) in &[
        (config.exclude, "AssertImplConfig::exclude"),
        (config.not_send, "AssertImplConfig::not_send"),
        (config.not_sync, "AssertImplConfig::not_sync"),
        (config.not_unpin, "AssertImplConfig::not_unpin"),
        (config.not_unwind_safe, "AssertImplConfig::not_unwind_safe"),
        (config.not_ref_unwind_safe, "AssertImplConfig::not_ref_unwind_safe"),
    ] {
        if name.starts_with("AssertImplConfig::not_") {
            use_macros |= !list.is_empty();
        }
        for &ty in *list {
            assert!(
                visited_types.contains(ty),
                "unknown type `{}` specified in {} field",
                ty,
                name
            );
        }
    }

    let mut out = quote! {
        #![allow(
            dead_code,
            unused_macros,
            clippy::std_instead_of_alloc,
            clippy::std_instead_of_core,
        )]
        fn assert_send<T: ?Sized + Send>() {}
        fn assert_sync<T: ?Sized + Sync>() {}
        fn assert_unpin<T: ?Sized + Unpin>() {}
        fn assert_unwind_safe<T: ?Sized + std::panic::UnwindSafe>() {}
        fn assert_ref_unwind_safe<T: ?Sized + std::panic::RefUnwindSafe>() {}
    };
    if use_generics_helpers {
        out.extend(quote! {
            /// `Send` & `!Sync`
            struct NotSync(core::cell::UnsafeCell<()>);
            /// `!Send` & `Sync`
            struct NotSend(std::sync::MutexGuard<'static, ()>);
            /// `!Send` & `!Sync`
            struct NotSendSync(*const ());
            /// `!Unpin`
            struct NotUnpin(core::marker::PhantomPinned);
            /// `!UnwindSafe`
            struct NotUnwindSafe(&'static mut ());
            /// `!RefUnwindSafe`
            struct NotRefUnwindSafe(core::cell::UnsafeCell<()>);
        });
    }
    if use_macros {
        out.extend(quote! {
            macro_rules! assert_not_send {
                ($ty:ty) => {
                    static_assertions::assert_not_impl_all!($ty: Send);
                };
            }
            macro_rules! assert_not_sync {
                ($ty:ty) => {
                    static_assertions::assert_not_impl_all!($ty: Sync);
                };
            }
            macro_rules! assert_not_unpin {
                ($ty:ty) => {
                    static_assertions::assert_not_impl_all!($ty: Unpin);
                };
            }
            macro_rules! assert_not_unwind_safe {
                ($ty:ty) => {
                    static_assertions::assert_not_impl_all!($ty: std::panic::UnwindSafe);
                };
            }
            macro_rules! assert_not_ref_unwind_safe {
                ($ty:ty) => {
                    static_assertions::assert_not_impl_all!($ty: std::panic::RefUnwindSafe);
                };
            }
        });
    }
    out.extend(quote! {
        const _: fn() = || {
            #tokens
        };
    });
    (out_dir.join("assert_impl.rs"), out)
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
        #[rustversion::attr(
            nightly,
            cfg_attr(any(not(target_pointer_width = "64"), miri, careful), ignore)
        )]
        #[rustversion::attr(not(nightly), ignore)]
        #[test]
        fn track_size() {
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
