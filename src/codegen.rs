// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    string::ToString as _,
    vec,
    vec::Vec,
};

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

                let has_generics = generics.type_params().count() != 0;
                let has_lifetimes = generics.lifetimes().count() != 0;
                assert_eq!(
                    generics.const_params().count(),
                    0,
                    "gen_assert_impl doesn't support const generics yet; skipped `{}`",
                    path_string
                );

                let lt = generics.lifetimes().map(|_| quote! { '_ });
                if has_generics {
                    let lt = quote! { #(#lt,)* };
                    use_generics_helpers = true;
                    // Send & Sync & Unpin & UnwindSafe & RefUnwindSafe
                    let unit = generics.type_params().map(|_| quote! { () });
                    let unit_generics = quote! { <#lt #(#unit),*> };
                    // !Send & Sync
                    let not_send = generics.type_params().map(|_| quote! { NotSend });
                    let not_send_generics = quote! { <#lt #(#not_send),*> };
                    // Send & !Sync
                    let not_sync = generics.type_params().map(|_| quote! { NotSync });
                    let not_sync_generics = quote! { <#lt #(#not_sync),*> };
                    // !Unpin
                    let not_unpin = generics.type_params().map(|_| quote! { NotUnpin });
                    let not_unpin_generics = quote! { <#lt #(#not_unpin),*> };
                    // !UnwindSafe
                    let not_unwind_safe = generics.type_params().map(|_| quote! { NotUnwindSafe });
                    let not_unwind_safe_generics = quote! { <#lt #(#not_unwind_safe),*> };
                    // !RefUnwindSafe
                    let not_ref_unwind_safe =
                        generics.type_params().map(|_| quote! { NotRefUnwindSafe });
                    let not_ref_unwind_safe_generics = quote! { <#lt #(#not_ref_unwind_safe),*> };
                    if config.not_send.contains(&path_string.as_str()) {
                        tokens.extend(quote! {
                            assert_not_send!(crate:: #(#module::)* #ident #unit_generics);
                        });
                    } else {
                        tokens.extend(quote! {
                            assert_send::<crate:: #(#module::)* #ident #unit_generics>();
                            assert_send::<crate:: #(#module::)* #ident #not_sync_generics>();
                            assert_not_send!(crate:: #(#module::)* #ident #not_send_generics);
                        });
                    }
                    if config.not_sync.contains(&path_string.as_str()) {
                        tokens.extend(quote! {
                            assert_not_sync!(crate:: #(#module::)* #ident #unit_generics);
                        });
                    } else {
                        tokens.extend(quote! {
                            assert_sync::<crate:: #(#module::)* #ident #unit_generics>();
                            assert_sync::<crate:: #(#module::)* #ident #not_send_generics>();
                            assert_not_sync!(crate:: #(#module::)* #ident #not_sync_generics);
                        });
                    }
                    if config.not_unpin.contains(&path_string.as_str()) {
                        tokens.extend(quote! {
                            assert_not_unpin!(crate:: #(#module::)* #ident #unit_generics);
                        });
                    } else {
                        tokens.extend(quote! {
                            assert_unpin::<crate:: #(#module::)* #ident #unit_generics>();
                            assert_not_unpin!(crate:: #(#module::)* #ident #not_unpin_generics);
                        });
                    }
                    if config.not_unwind_safe.contains(&path_string.as_str()) {
                        tokens.extend(quote! {
                            assert_not_unwind_safe!(crate:: #(#module::)* #ident #unit_generics);
                        });
                    } else {
                        tokens.extend(quote! {
                            assert_unwind_safe::<crate:: #(#module::)* #ident #unit_generics>();
                            assert_not_unwind_safe!(
                                crate:: #(#module::)* #ident #not_unwind_safe_generics
                            );
                        });
                    }
                    if config.not_ref_unwind_safe.contains(&path_string.as_str()) {
                        tokens.extend(quote! {
                            assert_not_ref_unwind_safe!(
                                crate:: #(#module::)* #ident #unit_generics
                            );
                        });
                    } else {
                        tokens.extend(quote! {
                            assert_ref_unwind_safe::<crate:: #(#module::)* #ident #unit_generics>();
                            assert_not_ref_unwind_safe!(
                                crate:: #(#module::)* #ident #not_ref_unwind_safe_generics
                            );
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
    use std::{eprintln, format, io, path::Path, string::String, sync::OnceLock, vec, vec::Vec};

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
    ) -> io::Result<()> {
        write_raw(function_name, bin_name, workspace_root, path.as_ref(), format_tokens(&contents))
    }

    #[track_caller]
    pub fn write_raw(
        function_name: &str,
        bin_name: &str,
        workspace_root: &Path,
        path: &Path,
        contents: impl AsRef<[u8]>,
    ) -> io::Result<()> {
        static LINGUIST_GENERATED: OnceLock<Vec<globset::GlobMatcher>> = OnceLock::new();
        let linguist_generated = LINGUIST_GENERATED.get_or_init(|| {
            let gitattributes = fs::read_to_string(workspace_root.join(".gitattributes")).unwrap();
            let mut linguist_generated = vec![];
            for line in gitattributes.lines() {
                if line.contains("linguist-generated") {
                    linguist_generated.push(
                        globset::Glob::new(line.split_once(' ').unwrap().0)
                            .unwrap()
                            .compile_matcher(),
                    );
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
        if path.is_file() && fs::read(path)? == out {
            return Ok(());
        }
        fs::write(path, out)?;
        eprintln!("updated {}", p.display());
        Ok(())
    }

    #[track_caller]
    fn format_tokens(contents: &TokenStream) -> Vec<u8> {
        let mut out = prettyplease::unparse(
            &syn::parse2(contents.clone())
                .unwrap_or_else(|e| panic!("{} in:\n---\n{}\n---", e, contents)),
        )
        .into_bytes();
        format_macros(&mut out);
        out
    }

    // Roughly format the code inside macro calls.
    fn format_macros(bytes: &mut Vec<u8>) {
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i..].starts_with(b"!(") {
                i += 2;
                let mut count = 0;
                while let Some(b) = bytes.get(i) {
                    match b {
                        b'(' => count += 1,
                        b')' => {
                            if count == 0 {
                                break;
                            }
                            count -= 1;
                        }
                        _ => {
                            fn replace(
                                bytes: &mut Vec<u8>,
                                i: usize,
                                needle: &[u8],
                                with: &[u8],
                            ) -> usize {
                                if bytes[i..].starts_with(needle) {
                                    bytes.splice(i..i + needle.len(), with.iter().copied());
                                    i + with.len() - 1
                                } else {
                                    i
                                }
                            }
                            i = replace(bytes, i, b"crate ::", b"crate::");
                            i = replace(bytes, i, b" < ", b"<");
                            i = replace(bytes, i, b" >", b">");
                        }
                    }
                    i += 1;
                }
            } else {
                i += 1;
            }
        }
    }
    #[test]
    fn test_format_macros() {
        #[track_caller]
        fn t(from: &[u8], expected: &[u8]) {
            let b = &mut from.to_vec();
            format_macros(b);
            assert_eq!(b, expected);
        }
        t(b"m!(crate ::a::b)", b"m!(crate::a::b)");
        t(b"(crate ::a::b)", b"(crate ::a::b)");
        t(b"m!(crate ::a::b < () >)", b"m!(crate::a::b<()>)");
        t(b"m!(crate ::a::b <  >)", b"m!(crate::a::b<>)");
        t(b"if < 0 ", b"if < 0 ");
        t(b"if > 0 ", b"if > 0 ");
    }
}
