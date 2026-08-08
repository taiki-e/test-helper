// SPDX-License-Identifier: Apache-2.0 OR MIT

#![no_std]
#![warn(unsafe_op_in_unsafe_fn)]
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
#[cfg(feature = "std")]
pub mod once_lock;
#[cfg(feature = "sys")]
#[path = "gen/sys/mod.rs"]
pub mod sys;
#[cfg(feature = "sys")]
mod sys_macros;
#[cfg(all(feature = "valgrind", valgrind))]
pub mod valgrind;
