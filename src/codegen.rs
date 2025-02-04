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
use quote::{format_ident, quote, ToTokens as _};
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
        /// Test the size of public types. This is not intended to keep a specific size and
        /// is intended to be used only as a help in optimization.
        ///
        /// Ignore non-64-bit targets due to usize/ptr size, and ignore Miri/cargo-careful
        /// as we set -Z randomize-layout for them.
        #[test]
        #[cfg_attr(any(not(target_pointer_width = "64"), miri, careful), ignore)] // We set -Z randomize-layout for Miri/cargo-careful.
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
