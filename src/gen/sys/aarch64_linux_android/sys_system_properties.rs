// SPDX-License-Identifier: Apache-2.0 OR MIT
// This file is @generated by portable-atomic-internal-codegen
// (gen function at tools/codegen/src/ffi.rs).
// It is not intended for manual editing.

#![cfg_attr(rustfmt, rustfmt::skip)]

pub const PROP_VALUE_MAX: u32 = 92;
extern "C" {
    pub fn __system_property_get(
        __name: *const ::std::os::raw::c_char,
        __value: *mut ::std::os::raw::c_char,
    ) -> ::std::os::raw::c_int;
}
