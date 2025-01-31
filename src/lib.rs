// SPDX-License-Identifier: Apache-2.0 OR MIT

#![no_std]
#![warn(unsafe_op_in_unsafe_fn)]
#![allow(
    clippy::missing_panics_doc,
    clippy::new_without_default,
    clippy::undocumented_unsafe_blocks
)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "cli")]
pub mod cli;
#[cfg(feature = "cpuinfo")]
pub mod cpuinfo;
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
