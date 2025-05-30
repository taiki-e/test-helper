// SPDX-License-Identifier: Apache-2.0 OR MIT
// This file is @generated by test-helper-internal-codegen
// (generate function at tools/codegen/src/ffi.rs).
// It is not intended for manual editing.

#![cfg_attr(rustfmt, rustfmt::skip)]

extern "C" {
    pub fn dlsym(
        __handle: *mut ::core::ffi::c_void,
        __symbol: *const ::std::os::raw::c_char,
    ) -> *mut ::core::ffi::c_void;
}
pub const RTLD_DEFAULT: *mut ::std::os::raw::c_void = 4294967295u32
    as *mut ::std::os::raw::c_void;
