// SPDX-License-Identifier: Apache-2.0 OR MIT
// This file is @generated by test-helper-internal-codegen
// (gen function at tools/codegen/src/ffi.rs).
// It is not intended for manual editing.

#![cfg_attr(rustfmt, rustfmt::skip)]

extern "C" {
    pub fn getauxval(arg1: ::std::os::raw::c_ulong) -> ::std::os::raw::c_ulong;
}
