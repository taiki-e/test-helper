// SPDX-License-Identifier: Apache-2.0 OR MIT

/*!
<!-- Note: Document from sync-markdown-to-rustdoc:start through sync-markdown-to-rustdoc:end
     is synchronized from README.md. Any changes to that range are not preserved. -->
<!-- tidy:sync-markdown-to-rustdoc:start -->

This crate contains some helpers used by tests and internal tools in projects managed by @taiki-e.

Originally extracted from test-helper from [portable-atomic](https://github.com/taiki-e/portable-atomic) repository.

There are no stability guarantees for these helpers, since they're
supposed to only be used in projects managed by us.

<!-- tidy:sync-markdown-to-rustdoc:end -->
*/

#![no_std]
#![doc(test(
    no_crate_inject,
    attr(allow(
        dead_code,
        unused_variables,
        clippy::undocumented_unsafe_blocks,
        clippy::unused_trait_names,
    ))
))]
#![warn(unsafe_op_in_unsafe_fn)]
#![warn(
    // Lints that may help when writing public library.
    // missing_debug_implementations,
    // missing_docs,
    clippy::alloc_instead_of_core,
    // clippy::exhaustive_enums,
    // clippy::exhaustive_structs,
    // clippy::impl_trait_in_params,
    // clippy::std_instead_of_alloc,
    // clippy::std_instead_of_core,
    // clippy::missing_inline_in_public_items,
)]
#![allow(
    clippy::missing_panics_doc,
    clippy::new_without_default,
    clippy::undocumented_unsafe_blocks
)]
#![cfg_attr(
    all(
        feature = "valgrind",
        valgrind,
        not(any(
            target_arch = "arm",
            target_arch = "aarch64",
            target_arch = "x86",
            target_arch = "x86_64",
            target_arch = "riscv32",
            target_arch = "riscv64",
            target_arch = "loongarch64",
            target_arch = "arm64ec",
            target_arch = "s390x",
            target_arch = "loongarch32",
            target_arch = "powerpc",
            target_arch = "powerpc64",
        )),
    ),
    feature(asm_experimental_arch)
)]

#[cfg(feature = "std")]
extern crate std;

#[macro_use]
mod macros;

// Not public API.
#[doc(hidden)]
pub mod __private {
    pub use core::{
        any::type_name,
        env,
        marker::{Send, Sized, Sync, Unpin},
        panic::{RefUnwindSafe, UnwindSafe},
        primitive::str,
    };
    #[cfg(feature = "std")]
    pub use std::{
        io::{Write, stderr},
        writeln,
    };
}

#[cfg(feature = "cli")]
pub mod cli;
#[cfg(feature = "codegen")]
pub mod codegen;
#[cfg(feature = "critical-section-std")]
mod critical_section_std;
#[cfg(feature = "doc")]
pub mod doc;
#[cfg(feature = "git")]
pub mod git;
pub mod marker;
#[cfg(feature = "std")]
pub mod once_lock;
#[cfg(all(feature = "valgrind", valgrind))]
pub mod valgrind;
