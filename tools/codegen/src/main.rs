// SPDX-License-Identifier: Apache-2.0 OR MIT

#![allow(
    clippy::assigning_clones,
    clippy::collapsible_else_if,
    clippy::enum_glob_use,
    clippy::needless_pass_by_value,
    clippy::unnecessary_wraps,
    clippy::wildcard_imports
)]

#[cfg(unix)]
mod ffi;

#[cfg(unix)]
fn workspace_root() -> &'static camino::Utf8Path {
    env!("CARGO_MANIFEST_DIR").strip_suffix("tools/codegen").unwrap().into()
}

fn main() {
    #[cfg(unix)]
    ffi::generate();
}
