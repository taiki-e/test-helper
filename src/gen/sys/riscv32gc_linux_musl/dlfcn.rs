// SPDX-License-Identifier: Apache-2.0 OR MIT
// This file is @generated by test-helper-internal-codegen
// (generate function at tools/codegen/src/ffi.rs).
// It is not intended for manual editing.

#![cfg_attr(rustfmt, rustfmt::skip)]

pub const RTLD_DEFAULT: *mut ::std::os::raw::c_void = ::core::ptr::null_mut();
extern "C" {
    pub fn dlsym(
        arg1: *mut ::core::ffi::c_void,
        arg2: *const ::std::os::raw::c_char,
    ) -> *mut ::core::ffi::c_void;
}
